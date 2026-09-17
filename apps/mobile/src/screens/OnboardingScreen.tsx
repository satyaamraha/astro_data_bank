/**
 * First run.
 *
 * Two things must be communicated honestly here, because getting them wrong
 * later is unrecoverable:
 *
 *  1. The account is a key, not a phone number. There is nothing to verify by
 *     SMS and nothing the operator can reset. That is the privacy win and the
 *     usability cost, and the user should understand it on day one.
 *
 *  2. The passphrase protects data at rest. If it is forgotten, the message
 *     history is gone — we cannot recover it, because we hold no copy of it.
 *     Promising otherwise would be a lie, so we say so plainly instead.
 */

import { useState } from 'react';
import { ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';
import { Button, Screen, SecurityNotice } from '../ui/components.js';
import { theme } from '../ui/theme.js';

/** Minimum passphrase length. Short enough to type, long enough to matter. */
const MIN_PASSPHRASE_LENGTH = 10;

export function OnboardingScreen({
  mode,
  onSubmit,
  busy,
  error,
}: {
  /** 'create' on first run; 'unlock' when a vault already exists on device. */
  mode: 'create' | 'unlock';
  onSubmit: (passphrase: string) => void;
  busy?: boolean;
  error?: string;
}) {
  const [passphrase, setPassphrase] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const creating = mode === 'create';

  const tooShort =
    creating && passphrase.length > 0 && passphrase.length < MIN_PASSPHRASE_LENGTH;
  const mismatch = creating && confirmation.length > 0 && confirmation !== passphrase;
  const ready = creating
    ? passphrase.length >= MIN_PASSPHRASE_LENGTH && confirmation === passphrase && !busy
    : passphrase.length > 0 && !busy;

  return (
    <Screen>
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        <Text style={styles.title}>Veil</Text>
        <Text style={styles.subtitle}>
          {creating ? 'Private messages and calls' : 'Welcome back'}
        </Text>

        {creating ? (
          <SecurityNotice
            tone="info"
            title="Your account is a key, not a phone number"
            body={
              'Veil never asks for a phone number or an email address. Your identity is ' +
              'a key generated on this device, so there is no personal detail for anyone ' +
              'to hand over, leak, or subpoena.'
            }
            style={styles.notice}
          />
        ) : null}

        <View style={styles.field}>
          <Text style={styles.label}>Passphrase</Text>
          <Text style={styles.hint}>
            {creating
              ? 'Unlocks this device. Use several unrelated words — length matters more than symbols.'
              : 'Unlocks your message history on this device.'}
          </Text>
          <TextInput
            accessibilityLabel="Passphrase"
            autoCapitalize="none"
            autoCorrect={false}
            onChangeText={setPassphrase}
            placeholder={creating ? 'at least 10 characters' : 'your passphrase'}
            placeholderTextColor={theme.colors.textFaint}
            secureTextEntry
            style={styles.input}
            value={passphrase}
          />
          {tooShort ? (
            <Text style={styles.error}>
              Use at least {MIN_PASSPHRASE_LENGTH} characters.
            </Text>
          ) : null}
        </View>

        {creating ? (
        <View style={styles.field}>
          <Text style={styles.label}>Confirm passphrase</Text>
          <TextInput
            accessibilityLabel="Confirm passphrase"
            autoCapitalize="none"
            autoCorrect={false}
            onChangeText={setConfirmation}
            placeholder="type it again"
            placeholderTextColor={theme.colors.textFaint}
            secureTextEntry
            style={styles.input}
            value={confirmation}
          />
          {mismatch ? <Text style={styles.error}>The passphrases do not match.</Text> : null}
        </View>
        ) : null}

        {creating ? (
          <SecurityNotice
            tone="caution"
            title="There is no password reset"
            body={
              'Your messages are encrypted with this passphrase and it never leaves this ' +
              'device. If you forget it, your history cannot be recovered — not by us, ' +
              'not by anyone. Write it down and keep it somewhere safe.'
            }
            style={styles.notice}
          />
        ) : null}

        {error !== undefined ? (
          <SecurityNotice
            tone="danger"
            title={creating ? 'Setup failed' : 'Could not unlock'}
            body={error}
            style={styles.notice}
          />
        ) : null}

        <Button
          label={creating ? 'Create my identity' : 'Unlock'}
          disabled={!ready}
          {...(busy !== undefined ? { loading: busy } : {})}
          onPress={() => onSubmit(passphrase)}
        />
      </ScrollView>
    </Screen>
  );
}

const styles = StyleSheet.create({
  content: {
    padding: theme.spacing(3),
    paddingTop: theme.spacing(8),
    gap: theme.spacing(2),
  },
  title: {
    color: theme.colors.text,
    fontSize: theme.font.display,
    fontWeight: '700',
    letterSpacing: 1,
  },
  subtitle: {
    color: theme.colors.textMuted,
    fontSize: theme.font.body,
    marginBottom: theme.spacing(1),
  },
  notice: {
    marginVertical: theme.spacing(0.5),
  },
  field: {
    gap: 6,
  },
  label: {
    color: theme.colors.text,
    fontSize: theme.font.small,
    fontWeight: '600',
  },
  hint: {
    color: theme.colors.textMuted,
    fontSize: theme.font.small,
    lineHeight: 18,
  },
  input: {
    backgroundColor: theme.colors.surface,
    borderColor: theme.colors.border,
    borderRadius: theme.radius.small,
    borderWidth: 1,
    color: theme.colors.text,
    fontSize: theme.font.body,
    minHeight: 48,
    paddingHorizontal: theme.spacing(1.5),
  },
  error: {
    color: theme.colors.danger,
    fontSize: theme.font.small,
  },
});
