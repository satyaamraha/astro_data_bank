/**
 * Shared UI pieces.
 *
 * `VerificationBadge` and `SecurityNotice` exist because the cryptography is
 * only as good as the user's ability to read its state. Both pair colour with
 * a glyph and a word, so the meaning survives colourblindness, glare, and a
 * quick glance.
 */

import type { ReactNode } from 'react';
import {
  ActivityIndicator,
  Pressable,
  StyleSheet,
  Text,
  View,
  type StyleProp,
  type ViewStyle,
} from 'react-native';
import { theme } from './theme.js';
import type { VerificationState } from '../core/types.js';

export function Screen({ children }: { children: ReactNode }) {
  return <View style={styles.screen}>{children}</View>;
}

export function Button({
  label,
  onPress,
  variant = 'primary',
  disabled,
  loading,
}: {
  label: string;
  onPress: () => void;
  variant?: 'primary' | 'secondary' | 'danger';
  disabled?: boolean;
  loading?: boolean;
}) {
  const background =
    variant === 'primary'
      ? theme.colors.accent
      : variant === 'danger'
        ? theme.colors.danger
        : theme.colors.surfaceRaised;
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled: disabled === true || loading === true }}
      disabled={disabled === true || loading === true}
      onPress={onPress}
      style={({ pressed }) => [
        styles.button,
        { backgroundColor: background, opacity: disabled === true ? 0.4 : pressed ? 0.8 : 1 },
      ]}
    >
      {loading === true ? (
        <ActivityIndicator color={theme.colors.text} />
      ) : (
        <Text style={styles.buttonLabel}>{label}</Text>
      )}
    </Pressable>
  );
}

const VERIFICATION_PRESENTATION: Record<
  VerificationState,
  { glyph: string; label: string; color: string }
> = {
  // Colour is paired with a glyph and a word in every case, so no single
  // channel carries the safety-critical meaning on its own.
  verified: { glyph: '✓', label: 'Verified', color: theme.colors.verified },
  unverified: { glyph: '?', label: 'Not verified', color: theme.colors.unverified },
  changed: { glyph: '!', label: 'Key changed', color: theme.colors.danger },
};

export function VerificationBadge({ state }: { state: VerificationState }) {
  const presentation = VERIFICATION_PRESENTATION[state];
  return (
    <View
      accessibilityLabel={`Contact status: ${presentation.label}`}
      style={[styles.badge, { borderColor: presentation.color }]}
    >
      <Text style={[styles.badgeGlyph, { color: presentation.color }]}>
        {presentation.glyph}
      </Text>
      <Text style={[styles.badgeLabel, { color: presentation.color }]}>
        {presentation.label}
      </Text>
    </View>
  );
}

/** A prominent, non-dismissible explanation of a security condition. */
export function SecurityNotice({
  tone,
  title,
  body,
  style,
}: {
  tone: 'info' | 'caution' | 'danger';
  title: string;
  body: string;
  style?: StyleProp<ViewStyle>;
}) {
  const color =
    tone === 'danger'
      ? theme.colors.danger
      : tone === 'caution'
        ? theme.colors.unverified
        : theme.colors.accent;
  return (
    <View style={[styles.notice, { borderLeftColor: color }, style]}>
      <Text style={[styles.noticeTitle, { color }]}>{title}</Text>
      <Text style={styles.noticeBody}>{body}</Text>
    </View>
  );
}

/**
 * Key material, grouped for comparison.
 *
 * Monospace and widely spaced, because the entire value of a safety number
 * depends on a human reading it aloud without transposing digits.
 */
export function KeyDigits({ value }: { value: string }) {
  return (
    <Text accessibilityLabel={value.split('').join(' ')} style={styles.keyDigits}>
      {value}
    </Text>
  );
}

export function Divider() {
  return <View style={styles.divider} />;
}

const styles = StyleSheet.create({
  screen: {
    flex: 1,
    backgroundColor: theme.colors.background,
  },
  button: {
    paddingVertical: theme.spacing(1.75),
    paddingHorizontal: theme.spacing(3),
    borderRadius: theme.radius.medium,
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: 48,
  },
  buttonLabel: {
    color: theme.colors.text,
    fontSize: theme.font.body,
    fontWeight: '600',
  },
  badge: {
    flexDirection: 'row',
    alignItems: 'center',
    borderWidth: 1,
    borderRadius: theme.radius.pill,
    paddingHorizontal: theme.spacing(1),
    paddingVertical: 2,
    gap: 4,
    alignSelf: 'flex-start',
  },
  badgeGlyph: {
    fontSize: theme.font.tiny,
    fontWeight: '800',
  },
  badgeLabel: {
    fontSize: theme.font.tiny,
    fontWeight: '600',
  },
  notice: {
    backgroundColor: theme.colors.surface,
    borderLeftWidth: 3,
    borderRadius: theme.radius.small,
    padding: theme.spacing(1.5),
    gap: 4,
  },
  noticeTitle: {
    fontSize: theme.font.small,
    fontWeight: '700',
  },
  noticeBody: {
    color: theme.colors.textMuted,
    fontSize: theme.font.small,
    lineHeight: 19,
  },
  keyDigits: {
    color: theme.colors.text,
    fontFamily: theme.font.mono,
    fontSize: theme.font.large,
    letterSpacing: 2,
    lineHeight: 30,
    textAlign: 'center',
  },
  divider: {
    height: StyleSheet.hairlineWidth,
    backgroundColor: theme.colors.border,
  },
});
