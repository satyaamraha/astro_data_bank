/**
 * Visual language.
 *
 * Dark by default, because this app gets used in places where a bright screen
 * draws attention.
 *
 * The colour choices carry meaning and are not decorative: verification state
 * is the one thing a user must read correctly, so `verified`, `unverified`, and
 * `danger` are deliberately far apart in both hue *and* lightness. Relying on
 * hue alone would make the most safety-critical distinction in the app
 * invisible to a red-green colourblind user.
 */

export const theme = {
  colors: {
    background: '#0B0E13',
    surface: '#151A22',
    surfaceRaised: '#1E252F',
    border: '#2A333F',
    text: '#E8ECF1',
    textMuted: '#8E9AAB',
    textFaint: '#5C6878',
    accent: '#5B8DEF',
    accentMuted: '#2C4470',
    /** Verified: a calm green, plus a check glyph so colour is never the only cue. */
    verified: '#3FB68B',
    /** Unverified: amber - caution, not failure. */
    unverified: '#D9A23B',
    /** Identity changed, or an unencrypted fallback: unmissable. */
    danger: '#E5484D',
    bubbleOutgoing: '#2C4470',
    bubbleIncoming: '#1E252F',
  },
  spacing: (units: number): number => units * 8,
  radius: {
    small: 8,
    medium: 14,
    large: 22,
    pill: 999,
  },
  font: {
    tiny: 11,
    small: 13,
    body: 15,
    large: 18,
    title: 24,
    display: 32,
    /** Monospace for key material: digits must be unambiguous when compared. */
    mono: 'Menlo',
  },
} as const;

export type VerificationColorKey = 'verified' | 'unverified' | 'danger';
