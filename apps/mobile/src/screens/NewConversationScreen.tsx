/**
 * Start a conversation.
 *
 * Two paths, and the screen is explicit that they are not equally strong:
 *
 *  - Pasting a **verification code** carries the full identity and its binding
 *    signature, so the conversation starts already verified.
 *  - Pasting an **address** only tells us where to look; the key comes from the
 *    relay, so the conversation starts unverified and must be checked by
 *    comparing safety numbers.
 *
 * Saying so here is the point. A UI that treated both as "add contact" would
 * leave users believing they had verified something they had not.
 */

import { useState } from 'react';
import { ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';
import { Button, Screen, SecurityNotice } from '../ui/components.js';
import { looksLikeCode } from '../core/display.js';
import { theme } from '../ui/theme.js';

export function NewConversationScreen({
  onStart,
  onBack,
  busy,
  error,
}: {
  onStart: (input: string, kind: 'code' | 'address') => void;
  onBack: () => void;
  busy?: boolean;
  error?: string;
}) {
  const [input, setInput] = useState('');
  const trimmed = input.trim();
  const kind: 'code' | 'address' = looksLikeCode(trimmed) ? 'code' : 'address';

  return (
    <Screen>
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        <Text style={styles.title}>New conversation</Text>

        <View style={styles.field}>
          <Text style={styles.label}>Their code or address</Text>
          <TextInput
            accessibilityLabel="Contact code or address"
            autoCapitalize="none"
            autoCorrect={false}
            multiline
            onChangeText={setInput}
            placeholder="paste a verification code, or type an address"
            placeholderTextColor={theme.colors.textFaint}
            style={styles.input}
            value={input}
          />
        </View>

        {trimmed.length === 0 ? null : kind === 'code' ? (
          <SecurityNotice
            tone="info"
            title="This is a verification code"
            body={
              'It contains their full identity and a signature proving the keys belong ' +
              'together, so this conversation will start already verified.'
            }
          />
        ) : (
          <SecurityNotice
            tone="caution"
            title="This is an address, not a verified key"
            body={
              'The key will come from the server, so the conversation starts unverified. ' +
              'Messages are still end-to-end encrypted, but compare safety numbers with ' +
              'your contact before trusting it.'
            }
          />
        )}

        {error !== undefined ? (
          <SecurityNotice tone="danger" title="Could not start" body={error} />
        ) : null}

        <View style={styles.actions}>
          <Button
            label={kind === 'code' ? 'Add verified contact' : 'Start unverified conversation'}
            disabled={trimmed.length === 0 || busy === true}
            {...(busy !== undefined ? { loading: busy } : {})}
            onPress={() => onStart(trimmed, kind)}
          />
          <Button label="Back" onPress={onBack} variant="secondary" />
        </View>
      </ScrollView>
    </Screen>
  );
}

const styles = StyleSheet.create({
  content: {
    gap: theme.spacing(2),
    padding: theme.spacing(3),
    paddingTop: theme.spacing(7),
  },
  title: {
    color: theme.colors.text,
    fontSize: theme.font.title,
    fontWeight: '700',
  },
  field: {
    gap: 6,
  },
  label: {
    color: theme.colors.text,
    fontSize: theme.font.small,
    fontWeight: '600',
  },
  input: {
    backgroundColor: theme.colors.surface,
    borderColor: theme.colors.border,
    borderRadius: theme.radius.small,
    borderWidth: 1,
    color: theme.colors.text,
    fontFamily: theme.font.mono,
    fontSize: theme.font.small,
    minHeight: 96,
    padding: theme.spacing(1.5),
    textAlignVertical: 'top',
  },
  actions: {
    gap: theme.spacing(1.25),
  },
});
