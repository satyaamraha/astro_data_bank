/**
 * Pairing: the one step that makes a two-person setup stronger than a
 * general messenger.
 *
 * The screen exists to get one thing right: that the codes are exchanged
 * **in person**. Everything else in Veil is arithmetic that holds regardless
 * of what the user does; this is the single point where the security depends
 * on human behaviour, so the instruction is the content of the screen rather
 * than fine print under it.
 *
 * The reason is worth stating to the user, and this screen does: if the code
 * arrives over any channel an attacker could tamper with, the attacker can
 * substitute their own code and read everything afterwards. No protocol can
 * detect that. Meeting up once removes the entire attack.
 */

import { useState } from 'react';
import { ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';
import { Button, Screen, SecurityNotice } from '../ui/components.js';
import { chunkCode } from '../core/display.js';
import { theme } from '../ui/theme.js';

export function PairScreen({
  myCode,
  onPair,
  onShareCode,
  busy,
  error,
}: {
  myCode: string;
  onPair: (theirCode: string, displayName: string) => void;
  onShareCode: () => void;
  busy?: boolean;
  error?: string;
}) {
  const [theirCode, setTheirCode] = useState('');
  const [displayName, setDisplayName] = useState('');

  const ready = theirCode.trim().length > 64 && !busy;

  return (
    <Screen>
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        <Text style={styles.title}>Pair your two phones</Text>
        <Text style={styles.subtitle}>
          Do this once, together, in the same room.
        </Text>

        <SecurityNotice
          tone="caution"
          title="Why it has to be in person"
          body={
            'If the code reaches you over anything someone could tamper with — SMS, ' +
            'email, another chat app — they can swap in their own code and read ' +
            'everything from then on, and nothing in the app can detect it. ' +
            'Exchanging codes face to face removes that risk completely.'
          }
        />

        <View style={styles.step}>
          <Text style={styles.stepTitle}>1 · Show them your code</Text>
          <View style={styles.codeCard}>
            {chunkCode(myCode).map((line, index) => (
              <Text key={index} selectable style={styles.code}>
                {line}
              </Text>
            ))}
          </View>
          <Button label="Share my code" onPress={onShareCode} variant="secondary" />
        </View>

        <View style={styles.step}>
          <Text style={styles.stepTitle}>2 · Paste their code</Text>
          <TextInput
            accessibilityLabel="Their pairing code"
            autoCapitalize="none"
            autoCorrect={false}
            multiline
            onChangeText={setTheirCode}
            placeholder="paste the code from their phone"
            placeholderTextColor={theme.colors.textFaint}
            style={styles.input}
            value={theirCode}
          />
          <TextInput
            accessibilityLabel="Their name"
            autoCorrect={false}
            onChangeText={setDisplayName}
            placeholder="what to call them (only stored on this phone)"
            placeholderTextColor={theme.colors.textFaint}
            style={styles.nameInput}
            value={displayName}
          />
        </View>

        <SecurityNotice
          tone="info"
          title="After pairing, this phone talks to nobody else"
          body={
            'Messages from any other account are discarded before they are even ' +
            'decrypted. If their key ever changes, the app stops rather than asking ' +
            'you to decide — you pair again, in person.'
          }
        />

        {error !== undefined ? (
          <SecurityNotice tone="danger" title="Could not pair" body={error} />
        ) : null}

        <Button
          label="Pair"
          disabled={!ready}
          {...(busy !== undefined ? { loading: busy } : {})}
          onPress={() => onPair(theirCode.trim(), displayName.trim())}
        />
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
  subtitle: {
    color: theme.colors.textMuted,
    fontSize: theme.font.body,
  },
  step: {
    gap: theme.spacing(1),
  },
  stepTitle: {
    color: theme.colors.text,
    fontSize: theme.font.body,
    fontWeight: '600',
  },
  codeCard: {
    backgroundColor: theme.colors.surface,
    borderColor: theme.colors.border,
    borderRadius: theme.radius.medium,
    borderWidth: 1,
    padding: theme.spacing(1.5),
  },
  code: {
    color: theme.colors.text,
    fontFamily: theme.font.mono,
    fontSize: theme.font.small,
    lineHeight: 20,
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
  nameInput: {
    backgroundColor: theme.colors.surface,
    borderColor: theme.colors.border,
    borderRadius: theme.radius.small,
    borderWidth: 1,
    color: theme.colors.text,
    fontSize: theme.font.body,
    minHeight: 48,
    paddingHorizontal: theme.spacing(1.5),
  },
});
