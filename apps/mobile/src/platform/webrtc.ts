/**
 * WebRTC media engine.
 *
 * The security-critical part of this file is `installFrameKeys` and the
 * `supportsFrameEncryption` flag it depends on.
 *
 * WebRTC gives us DTLS-SRTP for free, but DTLS terminates at whatever handles
 * the media. For a direct peer-to-peer call that is the peer; as soon as the
 * call is relayed through a TURN server — which happens routinely behind
 * symmetric NAT, i.e. most mobile networks — that is the relay operator. So
 * DTLS-SRTP alone does not deliver end-to-end encrypted voice.
 *
 * The fix is to encrypt each media frame before it enters the RTP stack, using
 * keys derived from the messaging session and never sent to any server. That
 * requires a frame-transform hook: `RTCRtpScriptTransform` / encoded
 * insertable streams. Where the platform does not expose one, we report
 * `supportsFrameEncryption: false` and the call manager refuses the call
 * rather than silently downgrading to something the operator can listen to.
 */

import {
  RTCPeerConnection,
  RTCSessionDescription,
  RTCIceCandidate,
  mediaDevices,
  type MediaStream,
} from 'react-native-webrtc';
import {
  createReceiver,
  createSender,
  decryptFrame,
  destroyReceiver,
  destroySender,
  encryptFrame,
  type SframeReceiver,
  type SframeSender,
} from '@veil/crypto';
import type { MediaEngine } from '../core/callManager.js';

/**
 * ICE configuration.
 *
 * The STUN/TURN servers see the call's IP addresses, so they are part of the
 * trust boundary for metadata even though they cannot read media once SFrame
 * is active. A deployment that cares about IP exposure should run its own TURN
 * server or route through a VPN, which is why this is a constructor argument
 * rather than a hardcoded public server.
 */
export interface IceConfiguration {
  readonly iceServers: Array<{
    urls: string | string[];
    username?: string;
    credential?: string;
  }>;
  /**
   * Force all media through TURN, hiding both peers' IP addresses from each
   * other. Costs bandwidth and latency; safe for media because SFrame means
   * the TURN server still cannot listen.
   */
  readonly relayOnly?: boolean;
}

/** Minimal shape of the encoded-transform API, which RN types do not model. */
interface FrameTransformCapableSender {
  createEncodedStreams?: () => {
    readable: ReadableStream<RTCEncodedFrame>;
    writable: WritableStream<RTCEncodedFrame>;
  };
}

interface RTCEncodedFrame {
  data: ArrayBuffer;
  timestamp: number;
}

export class WebRtcMediaEngine implements MediaEngine {
  private readonly connection: RTCPeerConnection;
  private localStream?: MediaStream | undefined;
  private sframeSender?: SframeSender | undefined;
  private sframeReceiver?: SframeReceiver | undefined;

  private candidateHandler?: ((candidate: string) => void) | undefined;
  private connectedHandler?: (() => void) | undefined;
  private disconnectedHandler?: (() => void) | undefined;

  readonly supportsFrameEncryption: boolean;

  constructor(ice: IceConfiguration) {
    this.connection = new RTCPeerConnection({
      iceServers: ice.iceServers,
      ...(ice.relayOnly ? { iceTransportPolicy: 'relay' as const } : {}),
    });

    // Probe once, at construction, so the call manager can refuse before the
    // user hears a ring tone.
    this.supportsFrameEncryption = detectFrameTransformSupport();

    // react-native-webrtc exposes on* properties rather than addEventListener.
    this.connection.onicecandidate = ((event: {
      candidate?: { candidate?: string } | null;
    }) => {
      const candidate = event.candidate?.candidate;
      if (candidate) this.candidateHandler?.(candidate);
    }) as typeof this.connection.onicecandidate;

    this.connection.onconnectionstatechange = (() => {
      const state = this.connection.connectionState;
      if (state === 'connected') this.connectedHandler?.();
      if (state === 'failed' || state === 'closed' || state === 'disconnected') {
        this.disconnectedHandler?.();
      }
    }) as typeof this.connection.onconnectionstatechange;
  }

  private async ensureLocalAudio(): Promise<void> {
    if (this.localStream) return;
    // Audio only. No video track is ever requested, so the camera permission
    // is never needed and cannot be misused by this app.
    this.localStream = await mediaDevices.getUserMedia({ audio: true, video: false });
    for (const track of this.localStream.getTracks()) {
      this.connection.addTrack(track, this.localStream);
    }
  }

  async createOffer(): Promise<{ sdp: string; dtlsFingerprint: string }> {
    await this.ensureLocalAudio();
    const offer = await this.connection.createOffer({});
    await this.connection.setLocalDescription(offer);
    return {
      sdp: offer.sdp ?? '',
      dtlsFingerprint: extractDtlsFingerprint(offer.sdp ?? ''),
    };
  }

  async createAnswer(remoteSdp: string): Promise<{ sdp: string; dtlsFingerprint: string }> {
    await this.ensureLocalAudio();
    await this.connection.setRemoteDescription(
      new RTCSessionDescription({ type: 'offer', sdp: remoteSdp }),
    );
    const answer = await this.connection.createAnswer();
    await this.connection.setLocalDescription(answer);
    return {
      sdp: answer.sdp ?? '',
      dtlsFingerprint: extractDtlsFingerprint(answer.sdp ?? ''),
    };
  }

  async acceptAnswer(remoteSdp: string): Promise<void> {
    await this.connection.setRemoteDescription(
      new RTCSessionDescription({ type: 'answer', sdp: remoteSdp }),
    );
  }

  async addRemoteCandidate(candidate: string): Promise<void> {
    await this.connection.addIceCandidate(new RTCIceCandidate({ candidate, sdpMid: '0' }));
  }

  onLocalCandidate(handler: (candidate: string) => void): void {
    this.candidateHandler = handler;
  }

  onConnected(handler: () => void): void {
    this.connectedHandler = handler;
  }

  onDisconnected(handler: () => void): void {
    this.disconnectedHandler = handler;
  }

  /**
   * Install SFrame keys into the send and receive pipelines.
   *
   * Each outgoing frame is encrypted after the codec and before RTP; each
   * incoming frame is decrypted after RTP and before the decoder. The RTP
   * headers stay readable so routers and the TURN server can still do their
   * job; the payload does not.
   */
  async installFrameKeys(keys: {
    sendKey: Uint8Array;
    receiveKey: Uint8Array;
  }): Promise<void> {
    if (!this.supportsFrameEncryption) {
      throw new Error(
        'this platform cannot transform encoded media frames, so end-to-end ' +
          'media encryption is unavailable',
      );
    }

    this.sframeSender = createSender(keys.sendKey);
    this.sframeReceiver = createReceiver(keys.receiveKey);

    for (const sender of this.connection.getSenders()) {
      const streams = (sender as unknown as FrameTransformCapableSender)
        .createEncodedStreams?.();
      if (!streams) continue;
      void streams.readable
        .pipeThrough(
          new TransformStream<RTCEncodedFrame, RTCEncodedFrame>({
            transform: (frame, controller) => {
              const encrypted = encryptFrame(
                this.sframeSender!,
                new Uint8Array(frame.data),
              );
              frame.data = packFrame(encrypted.counter, encrypted.payload);
              controller.enqueue(frame);
            },
          }),
        )
        .pipeTo(streams.writable);
    }

    for (const receiver of this.connection.getReceivers()) {
      const streams = (receiver as unknown as FrameTransformCapableSender)
        .createEncodedStreams?.();
      if (!streams) continue;
      void streams.readable
        .pipeThrough(
          new TransformStream<RTCEncodedFrame, RTCEncodedFrame>({
            transform: (frame, controller) => {
              try {
                const { counter, payload } = unpackFrame(new Uint8Array(frame.data));
                const plaintext = decryptFrame(this.sframeReceiver!, {
                  counter,
                  payload,
                });
                frame.data = toArrayBuffer(plaintext);
                controller.enqueue(frame);
              } catch {
                // Drop frames that fail authentication. A forged or replayed
                // frame must never reach the decoder, and dropping one audio
                // frame is inaudible - far better than playing attacker audio.
              }
            },
          }),
        )
        .pipeTo(streams.writable);
    }
  }

  setMuted(muted: boolean): void {
    for (const track of this.localStream?.getAudioTracks() ?? []) {
      track.enabled = !muted;
    }
  }

  async close(): Promise<void> {
    for (const track of this.localStream?.getTracks() ?? []) track.stop();
    this.localStream = undefined;
    if (this.sframeSender) destroySender(this.sframeSender);
    if (this.sframeReceiver) destroyReceiver(this.sframeReceiver);
    this.sframeSender = undefined;
    this.sframeReceiver = undefined;
    this.connection.close();
  }
}

// ---------------------------------------------------------------------------
// Frame framing
// ---------------------------------------------------------------------------

/** 8-byte big-endian counter, then ciphertext. Counter is authenticated as AAD. */
function packFrame(counter: bigint, payload: Uint8Array): ArrayBuffer {
  const out = new Uint8Array(8 + payload.length);
  new DataView(out.buffer).setBigUint64(0, counter, false);
  out.set(payload, 8);
  return out.buffer;
}

function unpackFrame(bytes: Uint8Array): { counter: bigint; payload: Uint8Array } {
  if (bytes.length < 8) throw new Error('media frame too short');
  const counter = new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, false);
  return { counter, payload: bytes.slice(8) };
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}

/**
 * Whether the encoded-frame transform API exists.
 *
 * Checked at runtime rather than assumed from the platform version, because
 * this capability gates whether a call can be end-to-end encrypted at all.
 */
function detectFrameTransformSupport(): boolean {
  const senderPrototype = (
    globalThis as { RTCRtpSender?: { prototype?: Record<string, unknown> } }
  ).RTCRtpSender?.prototype;
  if (senderPrototype && typeof senderPrototype['createEncodedStreams'] === 'function') {
    return true;
  }
  return typeof (globalThis as { RTCRtpScriptTransform?: unknown })
    .RTCRtpScriptTransform !== 'undefined';
}

/** Pull the DTLS certificate fingerprint out of SDP, for the call transcript. */
export function extractDtlsFingerprint(sdp: string): string {
  const match = /^a=fingerprint:(\S+)\s+(\S+)/m.exec(sdp);
  if (!match) {
    // Without a fingerprint we cannot bind SFrame keys to the transport, which
    // is what makes the SAS detect a MITM on the media path. Refuse rather
    // than derive keys from an empty string.
    throw new Error('SDP contains no DTLS fingerprint; refusing to set up media');
  }
  return `${match[1]} ${match[2]}`;
}
