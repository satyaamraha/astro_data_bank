import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { BACKGROUND_LOCK_GRACE_MS, shouldLock } from '../src/core/lockPolicy.js';

/**
 * Android build-configuration invariants.
 *
 * These assert properties of the generated native project. They exist because
 * platform hardening is exactly the kind of thing that regresses invisibly: a
 * dependency adds a permission, `expo prebuild` regenerates the manifest, and
 * nobody notices until an audit. Unlike the crypto, none of it is exercised by
 * running the app, so a test is the only thing that keeps it honest.
 *
 * `plugins/withAndroidPrivacy.js` is the source of truth; these check that the
 * committed output actually reflects it.
 */

const androidRoot = fileURLToPath(new URL('../android/', import.meta.url));
const read = (relative: string): string => readFileSync(join(androidRoot, relative), 'utf8');

const manifest = read('app/src/main/AndroidManifest.xml');
const appGradle = read('app/build.gradle');
const gradleProperties = read('gradle.properties');
const proguardRules = read('app/proguard-rules.pro');

describe('permissions', () => {
  /**
   * Permissions a private messenger must not hold.
   *
   * SYSTEM_ALERT_WINDOW and the storage permissions arrive transitively from
   * react-native-webrtc and expo modules, so they come back unless something
   * removes them. The rest are the ones messengers are routinely criticised
   * for requesting.
   */
  const forbidden = [
    'android.permission.SYSTEM_ALERT_WINDOW',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS',
    'android.permission.GET_ACCOUNTS',
    'android.permission.READ_PHONE_STATE',
    'android.permission.READ_PHONE_NUMBERS',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.CAMERA',
    'android.permission.READ_SMS',
    'android.permission.QUERY_ALL_PACKAGES',
  ];

  it.each(forbidden)('does not request %s', (permission) => {
    expect(manifest).not.toContain(permission);
  });

  it('requests only what voice calling and delivery need', () => {
    const requested = [...manifest.matchAll(/uses-permission android:name="([^"]+)"/g)].map(
      (match) => match[1],
    );
    // A closed list: anything new here is a deliberate decision, not a
    // dependency's side effect.
    expect(requested.sort()).toEqual(
      [
        'android.permission.FOREGROUND_SERVICE',
        'android.permission.FOREGROUND_SERVICE_MICROPHONE',
        'android.permission.INTERNET',
        'android.permission.MODIFY_AUDIO_SETTINGS',
        'android.permission.POST_NOTIFICATIONS',
        'android.permission.RECORD_AUDIO',
        'android.permission.VIBRATE',
      ].sort(),
    );
  });

  it('declares the typed microphone foreground service Android 14 requires', () => {
    // Without this, the platform kills a call as soon as the app backgrounds.
    expect(manifest).toContain('android.permission.FOREGROUND_SERVICE_MICROPHONE');
  });
});

describe('network policy', () => {
  it('forbids cleartext traffic', () => {
    expect(manifest).toContain('android:usesCleartextTraffic="false"');
  });

  it('applies a network security config', () => {
    expect(manifest).toContain('android:networkSecurityConfig="@xml/veil_network_security_config"');
  });

  it('does not trust user-installed certificate authorities', () => {
    // This is what stops a device-installed root CA - the standard corporate
    // or state interception setup - from transparently proxying the relay
    // connection.
    const config = read('app/src/main/res/xml/veil_network_security_config.xml');
    expect(config).toContain('cleartextTrafficPermitted="false"');
    expect(config).toContain('<certificates src="system" />');
    expect(config).not.toMatch(/<certificates\s+src="user"/);
  });
});

describe('backup and data extraction', () => {
  it('disables Android Backup', () => {
    expect(manifest).toContain('android:allowBackup="false"');
  });

  it('points at our own backup rules, not a permissive default', () => {
    expect(manifest).toContain('android:fullBackupContent="@xml/veil_backup_rules"');
    expect(manifest).toContain('android:dataExtractionRules="@xml/veil_data_extraction_rules"');
  });

  it('excludes every domain from cloud backup', () => {
    const rules = read('app/src/main/res/xml/veil_backup_rules.xml');
    for (const domain of ['root', 'file', 'database', 'sharedpref', 'external']) {
      expect(rules).toContain(`<exclude domain="${domain}" path="." />`);
    }
  });

  it('excludes every domain from device-to-device transfer too', () => {
    // A new-phone transfer would otherwise copy the encrypted database onto a
    // device whose keystore cannot open it.
    const rules = read('app/src/main/res/xml/veil_data_extraction_rules.xml');
    const transfer = rules.slice(rules.indexOf('<device-transfer>'));
    for (const domain of ['root', 'file', 'database', 'sharedpref', 'external']) {
      expect(transfer).toContain(`<exclude domain="${domain}" path="." />`);
    }
  });
});

describe('code integrity', () => {
  it('never signs a release with the debug keystore', () => {
    // The React Native template ships `signingConfig signingConfigs.debug` in
    // the release block, beside a committed keystore whose password is the
    // well-known "android". Shipping that would let anyone forge an update
    // the platform accepts as genuine.
    const releaseBlock = appGradle.slice(
      appGradle.indexOf('buildTypes {'),
      appGradle.indexOf('packagingOptions'),
    );
    const release = releaseBlock.slice(releaseBlock.indexOf('release {'));
    expect(release).toContain('signingConfig signingConfigs.release');
    expect(release).not.toContain('signingConfig signingConfigs.debug');
  });

  it('fails the build rather than producing an unsigned release', () => {
    expect(appGradle).toContain('Refusing to build a release without a signing key');
  });

  it('takes the release key from the environment, never from the repo', () => {
    expect(appGradle).toContain('VEIL_KEYSTORE_PATH');
    expect(appGradle).toContain('VEIL_KEY_PASSWORD');
    // No release keystore or password literal is committed.
    expect(appGradle).not.toMatch(/storePassword\s+['"](?!android')/);
  });

  it('disables over-the-air JavaScript updates', () => {
    // OTA delivery means the code on a user's phone is whatever the update
    // server sent, which defeats a reviewable, reproducibly built client.
    expect(manifest).toContain(
      '<meta-data android:name="expo.modules.updates.ENABLED" android:value="false"/>',
    );
    expect(manifest).toContain(
      '<meta-data android:name="expo.modules.updates.EXPO_UPDATES_CHECK_ON_LAUNCH" android:value="NEVER"/>',
    );
  });

  it('enables R8 shrinking and resource shrinking for release', () => {
    expect(gradleProperties).toContain('android.enableMinifyInReleaseBuilds=true');
    expect(gradleProperties).toContain('android.enableShrinkResourcesInReleaseBuilds=true');
  });
});

describe('R8 keep rules', () => {
  /**
   * R8 removes code it cannot see used, and React Native, Expo modules and
   * WebRTC all reach their native classes reflectively from JavaScript. Without
   * these keeps a release build compiles cleanly and then crashes in the field,
   * so the rules must survive every prebuild.
   */
  it.each([
    'com.facebook.react',
    'expo.modules',
    'org.webrtc',
    'com.oney.WebRTCModule',
  ])('keeps %s, which is reached by reflection', (packageName) => {
    expect(proguardRules).toContain(packageName);
  });

  it('keeps annotations and signatures', () => {
    expect(proguardRules).toContain('-keepattributes *Annotation*,Signature');
  });

  it('strips debug logging from release builds', () => {
    // Nothing here should log message content, but removing the calls means a
    // stray debug log added later cannot reach logcat.
    expect(proguardRules).toContain('-assumenosideeffects class android.util.Log');
  });
});

describe('platform floor', () => {
  it('requires Android 8 or newer', () => {
    // API 26 is the floor for the hardware-backed Keystore behaviour the
    // identity key storage relies on.
    const minSdk = /android\.minSdkVersion=(\d+)/.exec(gradleProperties);
    expect(minSdk).not.toBeNull();
    expect(Number(minSdk![1])).toBeGreaterThanOrEqual(26);
  });

  it('targets a current SDK', () => {
    // Targeting an old SDK opts out of platform hardening that newer versions
    // apply by default.
    const targetSdk = /android\.targetSdkVersion=(\d+)/.exec(gradleProperties);
    expect(targetSdk).not.toBeNull();
    expect(Number(targetSdk![1])).toBeGreaterThanOrEqual(34);
  });

  it('exposes no deep-link or intent surface beyond the launcher', () => {
    // Every exported component is an entry point an arbitrary app can poke.
    const intentFilters = [...manifest.matchAll(/<intent-filter>/g)];
    expect(intentFilters).toHaveLength(1);
    expect(manifest).toContain('android.intent.category.LAUNCHER');
  });
});

describe('lock policy', () => {
  it('does not lock while the app is in the foreground', () => {
    expect(shouldLock(undefined, 1_000_000)).toBe(false);
  });

  it('does not lock inside the grace period', () => {
    const backgrounded = 1_000_000;
    expect(shouldLock(backgrounded, backgrounded + BACKGROUND_LOCK_GRACE_MS - 1)).toBe(false);
  });

  it('locks once the grace period elapses', () => {
    const backgrounded = 1_000_000;
    expect(shouldLock(backgrounded, backgrounded + BACKGROUND_LOCK_GRACE_MS)).toBe(true);
  });

  it('locks after a long suspension, even though no timer ran', () => {
    // The OS can freeze the process and resume it hours later with the timer
    // still pending, so elapsed time is the authority.
    expect(shouldLock(1_000_000, 1_000_000 + 6 * 60 * 60 * 1000)).toBe(true);
  });

  it('locks when the clock moves backwards', () => {
    // An untrustworthy elapsed time must fail closed, never stay unlocked.
    expect(shouldLock(1_000_000, 500_000)).toBe(true);
  });

  it('uses a grace period short enough to matter', () => {
    expect(BACKGROUND_LOCK_GRACE_MS).toBeLessThanOrEqual(60_000);
  });
});
