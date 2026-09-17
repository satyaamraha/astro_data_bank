/**
 * A conversation.
 *
 * The persistent banner under the header is the important design decision: the
 * encryption state of the conversation is always visible while typing, not
 * buried in a menu. A user about to send something sensitive to an unverified
 * contact should not have to go looking for that fact.
 */

import { useState } from 'react';
import {
  FlatList,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import { Screen, SecurityNotice, VerificationBadge } from '../ui/components.js';
import { theme } from '../ui/theme.js';
import type { Contact, Message } from '../core/types.js';

const DISAPPEAR_OPTIONS = [
  { label: 'Off', seconds: 0 },
  { label: '1m', seconds: 60 },
  { label: '1h', seconds: 3600 },
  { label: '1d', seconds: 86_400 },
  { label: '1w', seconds: 604_800 },
] as const;

function statusGlyph(message: Message): string {
  switch (message.status) {
    case 'pending':
      return '◌';
    case 'sent':
      return '✓';
    case 'delivered':
      return '✓✓';
    case 'read':
      return '✓✓';
    case 'failed':
      return '✕';
    default:
      return '';
  }
}

export function ChatScreen({
  contact,
  messages,
  disappearAfterSeconds,
  onSend,
  onBack,
  onVerify,
  onCall,
  onChangeDisappear,
  sending,
}: {
  contact: Contact;
  messages: Message[];
  disappearAfterSeconds: number;
  onSend: (body: string) => void;
  onBack: () => void;
  onVerify: () => void;
  onCall: () => void;
  onChangeDisappear: (seconds: number) => void;
  sending?: boolean;
}) {
  const [draft, setDraft] = useState('');
  const [showTimer, setShowTimer] = useState(false);

  const submit = () => {
    const body = draft.trim();
    if (body.length === 0) return;
    setDraft('');
    onSend(body);
  };

  return (
    <Screen>
      <View style={styles.header}>
        <Pressable accessibilityLabel="Back" accessibilityRole="button" onPress={onBack}>
          <Text style={styles.back}>‹</Text>
        </Pressable>
        <Pressable accessibilityRole="button" onPress={onVerify} style={styles.headerCenter}>
          <Text style={styles.headerName} numberOfLines={1}>
            {contact.displayName}
          </Text>
          <VerificationBadge state={contact.verification} />
        </Pressable>
        <Pressable accessibilityLabel="Call" accessibilityRole="button" onPress={onCall}>
          <Text style={styles.callIcon}>✆</Text>
        </Pressable>
      </View>

      {contact.verification === 'changed' ? (
        <SecurityNotice
          tone="danger"
          title="This contact's key changed"
          body={
            'Their safety number is different from the one you verified. That usually ' +
            'means they reinstalled — but it is also what interception looks like. ' +
            'Tap their name to compare the new number before sending anything sensitive.'
          }
          style={styles.banner}
        />
      ) : contact.verification === 'unverified' ? (
        <SecurityNotice
          tone="caution"
          title="Encrypted, but not verified"
          body={
            'Messages here are end-to-end encrypted, and the server cannot read them. ' +
            'You have not yet checked that this key belongs to the right person — tap ' +
            'their name to compare safety numbers.'
          }
          style={styles.banner}
        />
      ) : null}

      <FlatList
        contentContainerStyle={styles.list}
        data={messages}
        inverted={false}
        keyExtractor={(message) => message.id}
        renderItem={({ item }) => {
          const outgoing = item.direction === 'outgoing';
          return (
            <View style={[styles.bubbleRow, outgoing ? styles.bubbleRowRight : null]}>
              <View
                style={[
                  styles.bubble,
                  outgoing ? styles.bubbleOutgoing : styles.bubbleIncoming,
                ]}
              >
                <Text style={styles.bubbleText}>{item.body}</Text>
                <View style={styles.bubbleMeta}>
                  {item.expiresAt !== undefined ? (
                    <Text style={styles.bubbleTimer} accessibilityLabel="Disappearing message">
                      ⏱
                    </Text>
                  ) : null}
                  {outgoing ? (
                    <Text
                      style={[
                        styles.bubbleStatus,
                        item.status === 'failed' ? styles.bubbleStatusFailed : null,
                      ]}
                    >
                      {statusGlyph(item)}
                    </Text>
                  ) : null}
                </View>
              </View>
            </View>
          );
        }}
      />

      {showTimer ? (
        <View style={styles.timerRow}>
          <Text style={styles.timerLabel}>Disappear after</Text>
          {DISAPPEAR_OPTIONS.map((option) => (
            <Pressable
              accessibilityRole="button"
              key={option.label}
              onPress={() => {
                onChangeDisappear(option.seconds);
                setShowTimer(false);
              }}
              style={[
                styles.timerOption,
                disappearAfterSeconds === option.seconds ? styles.timerOptionActive : null,
              ]}
            >
              <Text style={styles.timerOptionText}>{option.label}</Text>
            </Pressable>
          ))}
        </View>
      ) : null}

      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
        style={styles.composer}
      >
        <Pressable
          accessibilityLabel="Disappearing message timer"
          accessibilityRole="button"
          onPress={() => setShowTimer((value) => !value)}
          style={styles.timerToggle}
        >
          <Text
            style={[
              styles.timerToggleText,
              disappearAfterSeconds > 0 ? styles.timerToggleActive : null,
            ]}
          >
            ⏱
          </Text>
        </Pressable>
        <TextInput
          accessibilityLabel="Message"
          multiline
          onChangeText={setDraft}
          placeholder="Message"
          placeholderTextColor={theme.colors.textFaint}
          style={styles.input}
          value={draft}
        />
        <Pressable
          accessibilityLabel="Send"
          accessibilityRole="button"
          disabled={draft.trim().length === 0 || sending === true}
          onPress={submit}
          style={({ pressed }) => [
            styles.send,
            {
              opacity: draft.trim().length === 0 ? 0.35 : pressed ? 0.7 : 1,
            },
          ]}
        >
          <Text style={styles.sendText}>↑</Text>
        </Pressable>
      </KeyboardAvoidingView>
    </Screen>
  );
}

const styles = StyleSheet.create({
  header: {
    alignItems: 'center',
    borderBottomColor: theme.colors.border,
    borderBottomWidth: StyleSheet.hairlineWidth,
    flexDirection: 'row',
    gap: theme.spacing(1.5),
    paddingBottom: theme.spacing(1),
    paddingHorizontal: theme.spacing(2),
    paddingTop: theme.spacing(7),
  },
  back: {
    color: theme.colors.accent,
    fontSize: 34,
    lineHeight: 34,
  },
  headerCenter: {
    flex: 1,
    gap: 3,
  },
  headerName: {
    color: theme.colors.text,
    fontSize: theme.font.large,
    fontWeight: '600',
  },
  callIcon: {
    color: theme.colors.accent,
    fontSize: 24,
  },
  banner: {
    marginHorizontal: theme.spacing(2),
    marginTop: theme.spacing(1),
  },
  list: {
    gap: theme.spacing(1),
    padding: theme.spacing(2),
  },
  bubbleRow: {
    flexDirection: 'row',
  },
  bubbleRowRight: {
    justifyContent: 'flex-end',
  },
  bubble: {
    borderRadius: theme.radius.medium,
    maxWidth: '82%',
    paddingHorizontal: theme.spacing(1.5),
    paddingVertical: theme.spacing(1),
  },
  bubbleOutgoing: {
    backgroundColor: theme.colors.bubbleOutgoing,
    borderBottomRightRadius: 4,
  },
  bubbleIncoming: {
    backgroundColor: theme.colors.bubbleIncoming,
    borderBottomLeftRadius: 4,
  },
  bubbleText: {
    color: theme.colors.text,
    fontSize: theme.font.body,
    lineHeight: 21,
  },
  bubbleMeta: {
    alignSelf: 'flex-end',
    flexDirection: 'row',
    gap: 6,
    marginTop: 2,
  },
  bubbleTimer: {
    color: theme.colors.textFaint,
    fontSize: theme.font.tiny,
  },
  bubbleStatus: {
    color: theme.colors.textFaint,
    fontSize: theme.font.tiny,
  },
  bubbleStatusFailed: {
    color: theme.colors.danger,
  },
  timerRow: {
    alignItems: 'center',
    backgroundColor: theme.colors.surface,
    flexDirection: 'row',
    gap: 6,
    paddingHorizontal: theme.spacing(2),
    paddingVertical: theme.spacing(1),
  },
  timerLabel: {
    color: theme.colors.textMuted,
    fontSize: theme.font.small,
    marginRight: 4,
  },
  timerOption: {
    backgroundColor: theme.colors.surfaceRaised,
    borderRadius: theme.radius.pill,
    paddingHorizontal: theme.spacing(1.25),
    paddingVertical: 5,
  },
  timerOptionActive: {
    backgroundColor: theme.colors.accentMuted,
  },
  timerOptionText: {
    color: theme.colors.text,
    fontSize: theme.font.small,
  },
  composer: {
    alignItems: 'flex-end',
    borderTopColor: theme.colors.border,
    borderTopWidth: StyleSheet.hairlineWidth,
    flexDirection: 'row',
    gap: theme.spacing(1),
    padding: theme.spacing(1.5),
  },
  timerToggle: {
    paddingBottom: 10,
  },
  timerToggleText: {
    color: theme.colors.textFaint,
    fontSize: 20,
  },
  timerToggleActive: {
    color: theme.colors.accent,
  },
  input: {
    backgroundColor: theme.colors.surface,
    borderRadius: theme.radius.large,
    color: theme.colors.text,
    flex: 1,
    fontSize: theme.font.body,
    maxHeight: 120,
    minHeight: 44,
    paddingHorizontal: theme.spacing(1.75),
    paddingVertical: theme.spacing(1.25),
  },
  send: {
    alignItems: 'center',
    backgroundColor: theme.colors.accent,
    borderRadius: theme.radius.pill,
    height: 44,
    justifyContent: 'center',
    width: 44,
  },
  sendText: {
    color: theme.colors.text,
    fontSize: 20,
    fontWeight: '700',
  },
});
