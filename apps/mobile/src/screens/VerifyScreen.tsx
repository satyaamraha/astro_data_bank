/**
 * Contact verification.
 *
 * This screen is where end-to-end encryption stops being a claim and starts
 * being checkable. Everything else in the app can be correct and still be
 * defeated by an active attacker who substituted keys — unless the user
 * compares the number here through a channel the attacker does not control.
 *
 * Three deliberate choices:
 *
 *  - The instruction says *how* to compare (in person, or a call you recognise),
 *    because "compare this number" without a trusted channel is useless advice.
 *  - "Mark as verified" is the secondary action and scanning is primary, since
 *    scanning compares all 256 bits while a human reading digits aloud usually
 *    checks a prefix.
 *  - The key-changed state is explained in terms of both innocent and hostile
 *    causes, because telling users only the innocent one trains them to dismiss
 *    the warning.
 */

import { ScrollView, StyleSheet, Text, View } from 'react-native';
import { Button, KeyDigits, Screen, SecurityNotice, VerificationBadge } from '../ui/components.js';
import { theme } from '../ui/theme.js';
import type { Contact } from '../core/types.js';

/** Insert a space every five digits, matching how the number is read aloud. */
export function groupSafetyNumber(value: string): string[] {
  const groups: string[] = [];
  for (let i = 0; i < value.length; i += 5) groups.push(value.slice(i, i + 5));
  return groups;
}

export function VerifyScreen({
  contact,
  safetyNumber,
  onBack,
  onMarkVerified,
  onScanCode,
  onAcceptChange,
}: {
  contact: Contact;
  safetyNumber?: string;
  onBack: () => void;
  onMarkVerified: () => void;
  onScanCode: () => void;
  onAcceptChange: () => void;
}) {
  const groups = safetyNumber ? groupSafetyNumber(safetyNumber) : [];

  return (
    <Screen>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.title}>Verify {contact.displayName}</Text>
        <VerificationBadge state={contact.verification} />

        {contact.verification === 'changed' ? (
          <SecurityNotice
            tone="danger"
            title="The safety number changed"
            body={
              'Two things cause this. Usually your contact reinstalled the app or ' +
              'switched device, which generates a new key. But it is also exactly what ' +
              'happens if someone has stepped into the middle of your conversation. ' +
              'Compare the new number below before you accept it.'
            }
          />
        ) : null}

        <View style={styles.numberCard}>
          {safetyNumber ? (
            <>
              {[0, 1, 2, 3].map((line) => (
                <KeyDigits key={line} value={groups.slice(line * 3, line * 3 + 3).join(' ')} />
              ))}
            </>
          ) : (
            <Text style={styles.pending}>
              Send a message first — the safety number appears once you have exchanged keys.
            </Text>
          )}
        </View>

        <SecurityNotice
          tone="info"
          title="How to compare it"
          body={
            'Meet in person and scan each other&apos;s code, or read the digits aloud on a ' +
            'call where you recognise the voice. Do not compare it over this app or any ' +
            'other text channel: if someone can intercept your messages, they can ' +
            'intercept the number too.'
          }
        />

        <View style={styles.actions}>
          <Button label="Scan their code" onPress={onScanCode} />
          {contact.verification === 'changed' ? (
            <Button
              label="I compared it — accept the new key"
              onPress={onAcceptChange}
              variant="danger"
            />
          ) : (
            <Button
              label="The numbers match — mark verified"
              onPress={onMarkVerified}
              variant="secondary"
              disabled={safetyNumber === undefined || contact.verification === 'verified'}
            />
          )}
          <Button label="Back" onPress={onBack} variant="secondary" />
        </View>

        <Text style={styles.address}>{contact.address}</Text>
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
  numberCard: {
    backgroundColor: theme.colors.surface,
    borderColor: theme.colors.border,
    borderRadius: theme.radius.medium,
    borderWidth: 1,
    gap: 6,
    paddingHorizontal: theme.spacing(1),
    paddingVertical: theme.spacing(2.5),
  },
  pending: {
    color: theme.colors.textMuted,
    fontSize: theme.font.small,
    lineHeight: 20,
    paddingHorizontal: theme.spacing(1.5),
    textAlign: 'center',
  },
  actions: {
    gap: theme.spacing(1.25),
  },
  address: {
    color: theme.colors.textFaint,
    fontFamily: theme.font.mono,
    fontSize: theme.font.tiny,
    textAlign: 'center',
  },
});
