/**
 * Voice call state machine.
 *
 * Deliberately independent of WebRTC: it takes a `MediaEngine` interface, so
 * the call logic — which is where the security-relevant decisions live — is
 * testable without a device, a microphone, or a network.
 *
 * The security shape of a Veil call:
 *
 *  1. The caller generates a random media secret and sends it in a `call-offer`
 *     over the *message* channel, which is already end-to-end encrypted and
 *     mutually authenticated by identity keys. So call setup inherits the
 *     messaging layer's authentication instead of trusting a separate, weaker
 *     signalling path — the usual soft spot in "encrypted calling".
 *
 *  2. Both sides derive directional SFrame keys from that secret, bound to both
 *     identities and both DTLS certificate fingerprints.
 *
 *  3. Media is encrypted with those keys *inside* WebRTC's DTLS-SRTP. DTLS-SRTP
 *     alone terminates at whatever relays the media, so a TURN server would see
 *     plaintext audio; SFrame keys never leave the endpoints, so a relay
 *     carries audio it cannot decrypt.
 *
 *  4. Both users see the same four words. If a MITM terminated the media path,
 *     its DTLS fingerprint differs, the words differ, and the users detect it.
 *     The app must therefore *show* the words, and this module refuses to
 *     report a call as verified until the user confirms them.
 */

import {
  createCallSecrets,
  deriveCallKeys,
  random,
  toHex,
  type CallKeyMaterial,
  type CallRole,
  type PublicIdentity,
} from '@veil/crypto';
import { fromBase64Url, toBase64Url } from '@veil/protocol';
import type { CallInfo, Payload } from './types.js';

/**
 * What the platform's WebRTC stack must provide.
 *
 * `installFrameKeys` is the important one: it hands the SFrame keys to the
 * media pipeline (via encoded-transform / insertable streams on platforms that
 * support it). A platform that cannot do this must say so, because silently
 * falling back to DTLS-SRTP alone would mean the relay can hear the call — a
 * downgrade the user would never see. See `MediaEngine.supportsFrameEncryption`.
 */
export interface MediaEngine {
  /** True when per-frame encryption can actually be installed. */
  readonly supportsFrameEncryption: boolean;
  createOffer(): Promise<{ sdp: string; dtlsFingerprint: string }>;
  createAnswer(remoteSdp: string): Promise<{ sdp: string; dtlsFingerprint: string }>;
  acceptAnswer(remoteSdp: string): Promise<void>;
  addRemoteCandidate(candidate: string): Promise<void>;
  onLocalCandidate(handler: (candidate: string) => void): void;
  onConnected(handler: () => void): void;
  onDisconnected(handler: () => void): void;
  /** Install directional SFrame keys into the media pipeline. */
  installFrameKeys(keys: { sendKey: Uint8Array; receiveKey: Uint8Array }): Promise<void>;
  setMuted(muted: boolean): void;
  close(): Promise<void>;
}

export interface CallManagerOptions {
  readonly selfIdentity: PublicIdentity;
  readonly resolvePeerIdentity: (address: string) => PublicIdentity | undefined;
  readonly createMediaEngine: () => MediaEngine;
  readonly sendSignal: (peerAddress: string, payload: Payload) => Promise<void>;
  readonly events?: {
    onStateChange?: (call: CallInfo) => void;
    /** Called when the SAS is available. The UI must display it. */
    onSasAvailable?: (call: CallInfo) => void;
    onError?: (error: Error) => void;
  };
  /**
   * Refuse a call when the platform cannot install frame encryption.
   *
   * Default true. With frame encryption unavailable, media is protected only by
   * DTLS-SRTP, which a relaying TURN server terminates — so the operator could
   * listen. Allowing that silently would break the app's core promise, so the
   * default is to refuse and let the UI explain why.
   */
  readonly requireFrameEncryption?: boolean;
  readonly now?: () => number;
}

export class CallManager {
  private current?: CallInfo | undefined;
  private engine?: MediaEngine | undefined;
  private keys?: CallKeyMaterial | undefined;
  private mediaSecret?: Uint8Array | undefined;
  private localFingerprint?: string | undefined;
  private remoteFingerprint?: string | undefined;
  private readonly now: () => number;

  constructor(private readonly options: CallManagerOptions) {
    this.now = options.now ?? (() => Date.now());
  }

  get activeCall(): CallInfo | undefined {
    return this.current;
  }

  private requireFrameEncryption(): boolean {
    return this.options.requireFrameEncryption ?? true;
  }

  private setState(state: CallInfo['state'], extra: Partial<CallInfo> = {}): void {
    if (!this.current) return;
    this.current = { ...this.current, ...extra, state };
    this.options.events?.onStateChange?.(this.current);
  }

  // -------------------------------------------------------------------------
  // Placing a call
  // -------------------------------------------------------------------------

  async placeCall(peerAddress: string): Promise<CallInfo> {
    if (this.current && this.current.state !== 'ended') {
      throw new Error('a call is already in progress');
    }

    const engine = this.options.createMediaEngine();
    if (this.requireFrameEncryption() && !engine.supportsFrameEncryption) {
      await engine.close();
      throw new Error(
        'this device cannot encrypt call media end to end; refusing to place an unprotected call',
      );
    }

    const callId = toHex(random(16));
    this.current = {
      callId,
      peerAddress,
      direction: 'outgoing',
      state: 'ringing-outgoing',
      startedAt: this.now(),
    };
    this.engine = engine;
    this.attachEngineHandlers(engine, peerAddress, callId);

    const secrets = createCallSecrets();
    this.mediaSecret = secrets.mediaRootSecret;

    const offer = await engine.createOffer();
    this.localFingerprint = offer.dtlsFingerprint;

    await this.options.sendSignal(peerAddress, {
      kind: 'call-offer',
      callId,
      mediaSecret: toBase64Url(secrets.mediaRootSecret),
      sdp: offer.sdp,
      dtlsFingerprint: offer.dtlsFingerprint,
    });

    this.options.events?.onStateChange?.(this.current);
    return this.current;
  }

  // -------------------------------------------------------------------------
  // Receiving a call
  // -------------------------------------------------------------------------

  /** Handle an inbound signalling payload. Returns true if it was consumed. */
  async handleSignal(peerAddress: string, payload: Payload): Promise<boolean> {
    switch (payload.kind) {
      case 'call-offer':
        await this.onOffer(peerAddress, payload);
        return true;
      case 'call-answer':
        await this.onAnswer(peerAddress, payload);
        return true;
      case 'call-ice':
        if (this.current?.callId === payload.callId) {
          await this.engine?.addRemoteCandidate(payload.candidate);
        }
        return true;
      case 'call-hangup':
        if (this.current?.callId === payload.callId) {
          await this.endCall(payload.reason, false);
        }
        return true;
      default:
        return false;
    }
  }

  private async onOffer(
    peerAddress: string,
    payload: Extract<Payload, { kind: 'call-offer' }>,
  ): Promise<void> {
    if (this.current && this.current.state !== 'ended') {
      // Already busy: decline without disturbing the live call.
      await this.options.sendSignal(peerAddress, {
        kind: 'call-hangup',
        callId: payload.callId,
        reason: 'busy',
      });
      return;
    }

    this.current = {
      callId: payload.callId,
      peerAddress,
      direction: 'incoming',
      state: 'ringing-incoming',
      startedAt: this.now(),
    };
    this.mediaSecret = fromBase64Url(payload.mediaSecret);
    this.remoteFingerprint = payload.dtlsFingerprint;
    this.pendingOfferSdp = payload.sdp;
    this.options.events?.onStateChange?.(this.current);
  }

  private pendingOfferSdp?: string | undefined;

  /** Answer the ringing call. Derives keys and installs them before media flows. */
  async answerCall(): Promise<CallInfo> {
    const call = this.current;
    if (!call || call.state !== 'ringing-incoming' || !this.pendingOfferSdp) {
      throw new Error('no incoming call to answer');
    }

    const engine = this.options.createMediaEngine();
    if (this.requireFrameEncryption() && !engine.supportsFrameEncryption) {
      await engine.close();
      await this.options.sendSignal(call.peerAddress, {
        kind: 'call-hangup',
        callId: call.callId,
        reason: 'frame-encryption-unavailable',
      });
      this.setState('ended', { endReason: 'frame-encryption-unavailable' });
      throw new Error(
        'this device cannot encrypt call media end to end; refusing to answer',
      );
    }
    this.engine = engine;
    this.attachEngineHandlers(engine, call.peerAddress, call.callId);

    const answer = await engine.createAnswer(this.pendingOfferSdp);
    this.localFingerprint = answer.dtlsFingerprint;
    this.pendingOfferSdp = undefined;

    await this.deriveAndInstallKeys('callee');

    await this.options.sendSignal(call.peerAddress, {
      kind: 'call-answer',
      callId: call.callId,
      sdp: answer.sdp,
      dtlsFingerprint: answer.dtlsFingerprint,
    });

    this.setState('connecting');
    return this.current!;
  }

  private async onAnswer(
    peerAddress: string,
    payload: Extract<Payload, { kind: 'call-answer' }>,
  ): Promise<void> {
    const call = this.current;
    if (!call || call.callId !== payload.callId || call.peerAddress !== peerAddress) return;

    this.remoteFingerprint = payload.dtlsFingerprint;
    await this.engine?.acceptAnswer(payload.sdp);
    await this.deriveAndInstallKeys('caller');
    this.setState('connecting');
  }

  /**
   * Derive the SFrame keys and hand them to the media pipeline.
   *
   * Runs before the call is reported connected, so media is never carried
   * under DTLS-SRTP alone while we catch up.
   */
  private async deriveAndInstallKeys(role: CallRole): Promise<void> {
    const call = this.current;
    if (!call || !this.mediaSecret || !this.localFingerprint || !this.remoteFingerprint) {
      throw new Error('cannot derive call keys before setup completes');
    }

    const peerIdentity = this.options.resolvePeerIdentity(call.peerAddress);
    if (!peerIdentity) {
      throw new Error('no verified identity for the call peer');
    }

    const callerIdentity = role === 'caller' ? this.options.selfIdentity : peerIdentity;
    const calleeIdentity = role === 'caller' ? peerIdentity : this.options.selfIdentity;
    const callerFingerprint =
      role === 'caller' ? this.localFingerprint : this.remoteFingerprint;
    const calleeFingerprint =
      role === 'caller' ? this.remoteFingerprint : this.localFingerprint;

    this.keys = deriveCallKeys({
      secrets: { mediaRootSecret: this.mediaSecret },
      role,
      callerIdentity,
      calleeIdentity,
      callId: new TextEncoder().encode(call.callId),
      callerDtlsFingerprint: new TextEncoder().encode(callerFingerprint),
      calleeDtlsFingerprint: new TextEncoder().encode(calleeFingerprint),
    });

    await this.engine?.installFrameKeys({
      sendKey: this.keys.sendKey,
      receiveKey: this.keys.receiveKey,
    });

    this.current = {
      ...call,
      sas: this.keys.sas,
      sasDigits: this.keys.sasDigits,
    };
    // The UI must show these words. They are the only defence against an
    // active attacker who terminated the media path.
    this.options.events?.onSasAvailable?.(this.current);
    this.options.events?.onStateChange?.(this.current);
  }

  /** Record that the user confirmed the spoken words matched. */
  confirmSas(): void {
    if (!this.current) return;
    this.current = { ...this.current, sasConfirmed: true };
    this.options.events?.onStateChange?.(this.current);
  }

  private attachEngineHandlers(
    engine: MediaEngine,
    peerAddress: string,
    callId: string,
  ): void {
    engine.onLocalCandidate((candidate) => {
      void this.options
        .sendSignal(peerAddress, { kind: 'call-ice', callId, candidate })
        .catch((error: unknown) => {
          this.options.events?.onError?.(error as Error);
        });
    });
    engine.onConnected(() => {
      if (this.current?.callId === callId) this.setState('connected');
    });
    engine.onDisconnected(() => {
      if (this.current?.callId === callId) void this.endCall('disconnected', false);
    });
  }

  setMuted(muted: boolean): void {
    this.engine?.setMuted(muted);
  }

  /** End the call, wiping media keys. `notify` sends a hangup to the peer. */
  async endCall(reason = 'ended', notify = true): Promise<void> {
    const call = this.current;
    if (!call) return;

    if (notify && call.state !== 'ended') {
      try {
        await this.options.sendSignal(call.peerAddress, {
          kind: 'call-hangup',
          callId: call.callId,
          reason,
        });
      } catch {
        // The peer will time out; tearing down locally still matters more.
      }
    }

    await this.engine?.close();
    this.engine = undefined;

    // Wipe media key material so a later memory capture cannot recover the
    // call's audio keys.
    this.keys?.sendKey.fill(0);
    this.keys?.receiveKey.fill(0);
    this.mediaSecret?.fill(0);
    this.keys = undefined;
    this.mediaSecret = undefined;
    this.localFingerprint = undefined;
    this.remoteFingerprint = undefined;
    this.pendingOfferSdp = undefined;

    this.setState('ended', { endedAt: this.now(), endReason: reason });
  }
}
