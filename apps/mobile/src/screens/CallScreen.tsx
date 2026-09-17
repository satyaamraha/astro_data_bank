/**
 * Voice call.
 *
 * The four words are the centrepiece of this screen, not a detail in a corner.
 * They are the only way a user can detect an attacker who relayed the media
 * path, so the design makes reading them the obvious thing to do: large,
 * monospaced, with a one-line instruction and an explicit confirm control.
 *
 * Until the user confirms, the screen says the call is *not yet* verified. It
 * never claims more security than has actually been established.
 */

import { StyleSheet, Text, View } from 'react-native';
import { Button, Screen, SecurityNotice } from '../ui/components.js';
import { theme } from '../ui/theme.js';
import type { CallInfo } from '../core/types.js';

function stateLabel(call: CallInfo): string {
  switch (call.state) {
    case 'ringing-outgoing':
      return 'Calling…';
    case 'ringing-incoming':
      return 'Incoming call';
    case 'connecting':
      return 'Connecting…';
    case 'connected':
      return 'Connected';
    case 'ended':
      return call.endReason === undefined ? 'Call ended' : `Call ended · ${call.endReason}`;
    default:
      return '';
  }
}

function duration(call: CallInfo, now: number): string {
  if (call.state !== 'connected' || call.startedAt === undefined) return '';
  const seconds = Math.max(0, Math.floor((now - call.startedAt) / 1000));
  const minutes = Math.floor(seconds / 60);
  return `${minutes}:${String(seconds % 60).padStart(2, '0')}`;
}

export function CallScreen({
  call,
  peerName,
  muted,
  onAnswer,
  onHangUp,
  onToggleMute,
  onConfirmSas,
  now = Date.now(),
}: {
  call: CallInfo;
  peerName: string;
  muted: boolean;
  onAnswer: () => void;
  onHangUp: () => void;
  onToggleMute: () => void;
  onConfirmSas: () => void;
  now?: number;
}) {
  const showSas = call.sas !== undefined && call.state !== 'ended';

  return (
    <Screen>
      <View style={styles.content}>
        <View style={styles.identity}>
          <View style={styles.avatar}>
            <Text style={styles.avatarText}>{peerName.slice(0, 2).toUpperCase()}</Text>
          </View>
          <Text style={styles.name}>{peerName}</Text>
          <Text style={styles.state}>{stateLabel(call)}</Text>
          <Text style={styles.duration}>{duration(call, now)}</Text>
        </View>

        {showSas ? (
          <View style={styles.sasBlock}>
            <Text style={styles.sasPrompt}>Say these words out loud</Text>
            <Text
              accessibilityLabel={`Verification words: ${call.sas ?? ''}`}
              style={styles.sasWords}
            >
              {call.sas}
            </Text>
            <Text style={styles.sasDigits}>or read the digits: {call.sasDigits}</Text>

            {call.sasConfirmed === true ? (
              <SecurityNotice
                tone="info"
                title="Call verified"
                body={
                  'You confirmed the words matched, so nobody is relaying this call. The ' +
                  'audio is encrypted end to end and the server carries only ciphertext.'
                }
              />
            ) : (
              <>
                <SecurityNotice
                  tone="caution"
                  title="Not verified yet"
                  body={
                    'If your contact reads back different words, someone is sitting in ' +
                    'the middle of this call. Hang up and try again over a different ' +
                    'network.'
                  }
                />
                <Button label="The words matched" onPress={onConfirmSas} variant="secondary" />
              </>
            )}
          </View>
        ) : (
          <View style={styles.sasBlock}>
            <Text style={styles.sasPending}>
              Setting up encrypted audio… verification words appear in a moment.
            </Text>
          </View>
        )}

        <View style={styles.controls}>
          {call.state === 'ringing-incoming' ? (
            <Button label="Answer" onPress={onAnswer} />
          ) : (
            <Button
              label={muted ? 'Unmute' : 'Mute'}
              onPress={onToggleMute}
              variant="secondary"
            />
          )}
          <Button
            label={call.state === 'ended' ? 'Close' : 'Hang up'}
            onPress={onHangUp}
            variant="danger"
          />
        </View>
      </View>
    </Screen>
  );
}

const styles = StyleSheet.create({
  content: {
    flex: 1,
    justifyContent: 'space-between',
    padding: theme.spacing(3),
    paddingTop: theme.spacing(9),
  },
  identity: {
    alignItems: 'center',
    gap: theme.spacing(1),
  },
  avatar: {
    alignItems: 'center',
    backgroundColor: theme.colors.surfaceRaised,
    borderRadius: theme.radius.pill,
    height: 96,
    justifyContent: 'center',
    width: 96,
  },
  avatarText: {
    color: theme.colors.textMuted,
    fontSize: theme.font.title,
    fontWeight: '700',
  },
  name: {
    color: theme.colors.text,
    fontSize: theme.font.title,
    fontWeight: '600',
  },
  state: {
    color: theme.colors.textMuted,
    fontSize: theme.font.body,
  },
  duration: {
    color: theme.colors.textFaint,
    fontFamily: theme.font.mono,
    fontSize: theme.font.body,
  },
  sasBlock: {
    gap: theme.spacing(1.5),
  },
  sasPrompt: {
    color: theme.colors.textMuted,
    fontSize: theme.font.small,
    textAlign: 'center',
    textTransform: 'uppercase',
    letterSpacing: 1,
  },
  sasWords: {
    color: theme.colors.text,
    fontFamily: theme.font.mono,
    fontSize: theme.font.title,
    fontWeight: '700',
    letterSpacing: 1,
    lineHeight: 34,
    textAlign: 'center',
  },
  sasDigits: {
    color: theme.colors.textFaint,
    fontFamily: theme.font.mono,
    fontSize: theme.font.small,
    textAlign: 'center',
  },
  sasPending: {
    color: theme.colors.textMuted,
    fontSize: theme.font.small,
    textAlign: 'center',
  },
  controls: {
    gap: theme.spacing(1.25),
  },
});
