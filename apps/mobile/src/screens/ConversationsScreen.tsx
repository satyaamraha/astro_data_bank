/**
 * Conversation list.
 *
 * Shows verification state on every row rather than hiding it behind a tap.
 * A user who never opens a contact's detail page should still be able to see,
 * at a glance, which conversations have actually been verified — and a "key
 * changed" warning is the loudest thing on the screen, because it is the only
 * signal that distinguishes a reinstall from an active attack.
 */

import { FlatList, Pressable, StyleSheet, Text, View } from 'react-native';
import { Button, Divider, Screen, SecurityNotice, VerificationBadge } from '../ui/components.js';
import { theme } from '../ui/theme.js';
import { relativeTime } from '../core/display.js';
import type { Contact, Conversation } from '../core/types.js';

export interface ConversationRow {
  readonly conversation: Conversation;
  readonly contact?: Contact;
}

export function ConversationsScreen({
  rows,
  myAddress,
  onOpen,
  onNewConversation,
  onShowMyCode,
  now = Date.now(),
}: {
  rows: ConversationRow[];
  myAddress: string;
  onOpen: (address: string) => void;
  onNewConversation: () => void;
  onShowMyCode: () => void;
  now?: number;
}) {
  const changed = rows.filter((row) => row.contact?.verification === 'changed');

  return (
    <Screen>
      <View style={styles.header}>
        <View style={styles.headerText}>
          <Text style={styles.title}>Conversations</Text>
          <Pressable accessibilityRole="button" onPress={onShowMyCode}>
            <Text style={styles.myAddress} numberOfLines={1}>
              You: {myAddress}
            </Text>
          </Pressable>
        </View>
      </View>

      {changed.length > 0 ? (
        <SecurityNotice
          tone="danger"
          title={
            changed.length === 1
              ? 'A contact&apos;s key changed'
              : `${changed.length} contacts&apos; keys changed`
          }
          body={
            'This happens when someone reinstalls the app — but it is also what an ' +
            'interception attempt looks like. Verify again before sending anything ' +
            'sensitive.'
          }
          style={styles.warning}
        />
      ) : null}

      <FlatList
        data={rows}
        keyExtractor={(row) => row.conversation.address}
        ItemSeparatorComponent={Divider}
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={styles.emptyTitle}>No conversations yet</Text>
            <Text style={styles.emptyBody}>
              Share your code with someone, or scan theirs, to start a conversation.
            </Text>
          </View>
        }
        renderItem={({ item }) => {
          const { conversation, contact } = item;
          const name = contact?.displayName ?? conversation.address.slice(0, 12);
          return (
            <Pressable
              accessibilityRole="button"
              onPress={() => onOpen(conversation.address)}
              style={({ pressed }) => [styles.row, pressed ? styles.rowPressed : null]}
            >
              <View style={styles.avatar}>
                <Text style={styles.avatarText}>{name.slice(0, 2).toUpperCase()}</Text>
              </View>
              <View style={styles.rowBody}>
                <View style={styles.rowTop}>
                  <Text style={styles.rowName} numberOfLines={1}>
                    {name}
                  </Text>
                  <Text style={styles.rowTime}>
                    {relativeTime(conversation.lastMessageAt, now)}
                  </Text>
                </View>
                <Text style={styles.rowPreview} numberOfLines={1}>
                  {conversation.lastMessagePreview || 'No messages'}
                </Text>
                <VerificationBadge state={contact?.verification ?? 'unverified'} />
              </View>
              {conversation.unreadCount > 0 ? (
                <View style={styles.unread}>
                  <Text style={styles.unreadText}>{conversation.unreadCount}</Text>
                </View>
              ) : null}
            </Pressable>
          );
        }}
      />

      <View style={styles.footer}>
        <Button label="New conversation" onPress={onNewConversation} />
      </View>
    </Screen>
  );
}

const styles = StyleSheet.create({
  header: {
    paddingHorizontal: theme.spacing(2),
    paddingTop: theme.spacing(7),
    paddingBottom: theme.spacing(1.5),
  },
  headerText: {
    gap: 2,
  },
  title: {
    color: theme.colors.text,
    fontSize: theme.font.title,
    fontWeight: '700',
  },
  myAddress: {
    color: theme.colors.textFaint,
    fontFamily: theme.font.mono,
    fontSize: theme.font.tiny,
  },
  warning: {
    marginHorizontal: theme.spacing(2),
    marginBottom: theme.spacing(1),
  },
  row: {
    alignItems: 'center',
    flexDirection: 'row',
    gap: theme.spacing(1.5),
    paddingHorizontal: theme.spacing(2),
    paddingVertical: theme.spacing(1.5),
  },
  rowPressed: {
    backgroundColor: theme.colors.surface,
  },
  avatar: {
    alignItems: 'center',
    backgroundColor: theme.colors.surfaceRaised,
    borderRadius: theme.radius.pill,
    height: 44,
    justifyContent: 'center',
    width: 44,
  },
  avatarText: {
    color: theme.colors.textMuted,
    fontSize: theme.font.small,
    fontWeight: '700',
  },
  rowBody: {
    flex: 1,
    gap: 3,
  },
  rowTop: {
    alignItems: 'center',
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  rowName: {
    color: theme.colors.text,
    flex: 1,
    fontSize: theme.font.body,
    fontWeight: '600',
  },
  rowTime: {
    color: theme.colors.textFaint,
    fontSize: theme.font.tiny,
  },
  rowPreview: {
    color: theme.colors.textMuted,
    fontSize: theme.font.small,
  },
  unread: {
    alignItems: 'center',
    backgroundColor: theme.colors.accent,
    borderRadius: theme.radius.pill,
    justifyContent: 'center',
    minWidth: 22,
    paddingHorizontal: 6,
    paddingVertical: 2,
  },
  unreadText: {
    color: theme.colors.text,
    fontSize: theme.font.tiny,
    fontWeight: '700',
  },
  empty: {
    alignItems: 'center',
    gap: 8,
    padding: theme.spacing(5),
  },
  emptyTitle: {
    color: theme.colors.text,
    fontSize: theme.font.large,
    fontWeight: '600',
  },
  emptyBody: {
    color: theme.colors.textMuted,
    fontSize: theme.font.small,
    lineHeight: 20,
    textAlign: 'center',
  },
  footer: {
    borderTopColor: theme.colors.border,
    borderTopWidth: StyleSheet.hairlineWidth,
    padding: theme.spacing(2),
  },
});
