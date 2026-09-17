/**
 * Your own address and verification code.
 *
 * The code carries both public keys plus the binding signature, so a contact
 * who receives it through a channel they trust can verify the binding
 * themselves. That is strictly stronger than reading digits aloud, because it
 * compares all 256 bits instead of whatever prefix a human bothers to check.
 *
 * The screen says which channel to use, since a code delivered over a channel
 * the attacker controls proves nothing.
 */

import { ScrollView, StyleSheet, Text, View } from 'react-native';
import { Button, Screen, SecurityNotice } from '../ui/components.js';
import { chunkCode } from '../core/display.js';
import { theme } from '../ui/theme.js';

export function MyCodeScreen({
  address,
  code,
  onBack,
  onShare,
}: {
  address: string;
  code: string;
  onBack: () => void;
  onShare: () => void;
}) {
  return (
    <Screen>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.title}>Your code</Text>

        <View style={styles.card}>
          <Text style={styles.cardLabel}>Address</Text>
          <Text selectable style={styles.address}>
            {address}
          </Text>
        </View>

        <View style={styles.card}>
          <Text style={styles.cardLabel}>Verification code</Text>
          {chunkCode(code).map((line, index) => (
            <Text key={index} selectable style={styles.code}>
              {line}
            </Text>
          ))}
        </View>

        <SecurityNotice
          tone="info"
          title="Send this through a channel you trust"
          body={
            'Anyone who has this code can start a verified conversation with you. It ' +
            'contains only public keys — it cannot be used to read your messages or ' +
            'impersonate you. But a code delivered by someone who can tamper with the ' +
            'channel proves nothing, so hand it over in person where it matters.'
          }
        />

        <View style={styles.actions}>
          <Button label="Share my code" onPress={onShare} />
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
  card: {
    backgroundColor: theme.colors.surface,
    borderColor: theme.colors.border,
    borderRadius: theme.radius.medium,
    borderWidth: 1,
    gap: 4,
    padding: theme.spacing(2),
  },
  cardLabel: {
    color: theme.colors.textMuted,
    fontSize: theme.font.tiny,
    letterSpacing: 1,
    textTransform: 'uppercase',
  },
  address: {
    color: theme.colors.text,
    fontFamily: theme.font.mono,
    fontSize: theme.font.body,
    letterSpacing: 1,
  },
  code: {
    color: theme.colors.text,
    fontFamily: theme.font.mono,
    fontSize: theme.font.small,
    letterSpacing: 0.5,
    lineHeight: 20,
  },
  actions: {
    gap: theme.spacing(1.25),
  },
});
