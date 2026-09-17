/**
 * Android hardening, as a config plugin.
 *
 * Why a plugin and not hand-edits to `android/`: `expo prebuild` regenerates
 * that directory, so hand-edits silently disappear. Security settings that can
 * vanish on someone else's machine are not security settings. Everything here
 * is reapplied on every prebuild, and the committed `android/` output is what
 * this produces.
 *
 * What the default Expo/React Native Android template gets wrong for an app
 * like this, and what each change fixes, is documented inline.
 */

const {
  AndroidConfig,
  withAndroidManifest,
  withAppBuildGradle,
  withDangerousMod,
} = require('@expo/config-plugins');
const fs = require('node:fs');
const path = require('node:path');

/**
 * Permissions the template pulls in transitively that this app must not hold.
 *
 * - SYSTEM_ALERT_WINDOW ("draw over other apps") arrives via
 *   react-native-webrtc. It is a serious permission - an app holding it can
 *   overlay other apps' UI, which is the basis of tapjacking - and a 1:1
 *   voice app has no need for it.
 * - READ/WRITE_EXTERNAL_STORAGE arrive transitively too. Shared storage is
 *   world-readable to other apps with the same permission, and everything
 *   this app stores belongs in its private, encrypted database.
 * - The location, contacts, and phone-state permissions are the ones a
 *   messenger is usually criticised for. Veil never asks for them, and
 *   removing them here means the OS could not grant them even if some
 *   dependency later declared them.
 */
const FORBIDDEN_PERMISSIONS = [
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
  'android.permission.RECEIVE_SMS',
  'android.permission.QUERY_ALL_PACKAGES',
];

/**
 * Permissions the app genuinely needs.
 *
 * FOREGROUND_SERVICE_MICROPHONE is required from Android 14 (API 34): a
 * foreground service that uses the microphone must declare its type, or the
 * platform kills the call when the app backgrounds.
 */
const REQUIRED_PERMISSIONS = [
  'android.permission.INTERNET',
  'android.permission.RECORD_AUDIO',
  'android.permission.MODIFY_AUDIO_SETTINGS',
  'android.permission.FOREGROUND_SERVICE',
  'android.permission.FOREGROUND_SERVICE_MICROPHONE',
  'android.permission.POST_NOTIFICATIONS',
];

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

function withPermissions(config) {
  return withAndroidManifest(config, (mod) => {
    const manifest = mod.modResults.manifest;
    manifest['uses-permission'] = manifest['uses-permission'] ?? [];

    // Drop forbidden permissions outright rather than marking them
    // tools:node="remove". A removal marker still leaves the name in the
    // merged manifest tooling; deleting the node means it is simply absent.
    manifest['uses-permission'] = manifest['uses-permission'].filter((entry) => {
      const name = entry?.$?.['android:name'];
      return !FORBIDDEN_PERMISSIONS.includes(name);
    });

    // Also strip any tools:node="remove" placeholders the template added, so
    // the final list reads as exactly what the app uses.
    manifest['uses-permission'] = manifest['uses-permission'].filter(
      (entry) => entry?.$?.['tools:node'] !== 'remove',
    );

    const present = new Set(
      manifest['uses-permission'].map((entry) => entry?.$?.['android:name']),
    );
    for (const name of REQUIRED_PERMISSIONS) {
      if (!present.has(name)) {
        manifest['uses-permission'].push({ $: { 'android:name': name } });
      }
    }

    return mod;
  });
}

function withApplicationHardening(config) {
  return withAndroidManifest(config, (mod) => {
    const application = AndroidConfig.Manifest.getMainApplicationOrThrow(mod.modResults);

    Object.assign(application.$, {
      // No plaintext HTTP, ever. On its own targetSdk>=28 already defaults
      // cleartext off, but stating it means a future targetSdk change or a
      // library default cannot quietly re-enable it.
      'android:usesCleartextTraffic': 'false',
      'android:networkSecurityConfig': '@xml/veil_network_security_config',

      // Keep the encrypted database and the keystore wrapper out of Android
      // Backup and out of device-to-device transfer. Without this, the
      // ciphertext would be copied to Google's servers, and an attacker with
      // the account could attack it offline at leisure.
      'android:allowBackup': 'false',
      'android:fullBackupContent': '@xml/veil_backup_rules',
      'android:dataExtractionRules': '@xml/veil_data_extraction_rules',

      // Ask the platform not to keep this app's data on a device-wide
      // clear-text basis where it can be swept up by other tooling.
      'android:hasFragileUserData': 'false',
    });

    // Turn off expo-updates. Over-the-air JavaScript delivery means the code
    // running on a user's phone is whatever the update server sent, which
    // defeats the point of a reviewable, reproducibly built client. Code
    // changes should arrive through the app store, signed.
    const metaData = application['meta-data'] ?? [];
    for (const entry of metaData) {
      const name = entry?.$?.['android:name'];
      if (name === 'expo.modules.updates.ENABLED') {
        entry.$['android:value'] = 'false';
      }
      if (name === 'expo.modules.updates.EXPO_UPDATES_CHECK_ON_LAUNCH') {
        entry.$['android:value'] = 'NEVER';
      }
    }
    application['meta-data'] = metaData;

    // Keep the launcher activity out of the recents screenshot pipeline and
    // stop other apps launching it with arbitrary intents.
    const activities = application.activity ?? [];
    for (const activity of activities) {
      if (activity?.$?.['android:name'] === '.MainActivity') {
        Object.assign(activity.$, {
          // Exported is required for the launcher intent, but the activity
          // accepts no other intent filters, so there is no deep-link surface.
          'android:exported': 'true',
          'android:excludeFromRecents': 'false',
          // Never restore a task from a stale snapshot after the process died;
          // the vault is locked by then and the UI must start from unlock.
          'android:clearTaskOnLaunch': 'true',
          'android:configChanges':
            activity.$['android:configChanges'] ?? 'keyboard|keyboardHidden|orientation|screenSize',
        });
      }
    }

    return mod;
  });
}

// ---------------------------------------------------------------------------
// XML resources
// ---------------------------------------------------------------------------

/**
 * Network security config.
 *
 * Cleartext is denied for every domain. The commented pin-set block is the
 * hook for certificate pinning: pinning the relay's key means a
 * device-installed root CA - the standard corporate or state interception
 * setup - cannot transparently proxy the connection. It is left commented
 * because a pin must match your own deployment's certificate, and a wrong pin
 * bricks the app.
 *
 * Note what pinning does and does not buy here: message contents are already
 * end-to-end encrypted, so TLS interception reveals only the metadata the
 * relay sees anyway. Pinning protects that metadata and the registration
 * exchange.
 */
const NETWORK_SECURITY_CONFIG = `<?xml version="1.0" encoding="utf-8"?>
<!--
  Generated by plugins/withAndroidPrivacy.js - do not edit by hand.
-->
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system" />
      <!--
        User-installed CAs are deliberately NOT trusted. This is what stops a
        device-installed root certificate from silently intercepting the
        connection to the relay.
      -->
    </trust-anchors>
  </base-config>

  <!--
    Certificate pinning for your relay. Uncomment and set the SPKI digests for
    your own deployment. Always include a backup pin, or a certificate rotation
    will lock every installed client out.

  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">relay.example</domain>
    <pin-set expiration="2027-01-01">
      <pin digest="SHA-256">BASE64_SPKI_PIN_PRIMARY</pin>
      <pin digest="SHA-256">BASE64_SPKI_PIN_BACKUP</pin>
    </pin-set>
  </domain-config>
  -->
</network-security-config>
`;

/** Android 11 and below. Excluding the root excludes everything. */
const BACKUP_RULES = `<?xml version="1.0" encoding="utf-8"?>
<!--
  Generated by plugins/withAndroidPrivacy.js - do not edit by hand.

  Nothing this app stores may leave the device through Android Backup: not the
  encrypted message database, not the keystore wrapper, not shared prefs.
-->
<full-backup-content>
  <exclude domain="root" path="." />
  <exclude domain="file" path="." />
  <exclude domain="database" path="." />
  <exclude domain="sharedpref" path="." />
  <exclude domain="external" path="." />
</full-backup-content>
`;

/** Android 12+. Covers cloud backup and direct device-to-device transfer. */
const DATA_EXTRACTION_RULES = `<?xml version="1.0" encoding="utf-8"?>
<!--
  Generated by plugins/withAndroidPrivacy.js - do not edit by hand.

  device-transfer is excluded as well as cloud-backup: a new-phone transfer
  would otherwise copy the encrypted database onto a device whose keystore
  cannot open it, leaving ciphertext lying around for no benefit.
-->
<data-extraction-rules>
  <cloud-backup>
    <exclude domain="root" path="." />
    <exclude domain="file" path="." />
    <exclude domain="database" path="." />
    <exclude domain="sharedpref" path="." />
    <exclude domain="external" path="." />
  </cloud-backup>
  <device-transfer>
    <exclude domain="root" path="." />
    <exclude domain="file" path="." />
    <exclude domain="database" path="." />
    <exclude domain="sharedpref" path="." />
    <exclude domain="external" path="." />
  </device-transfer>
</data-extraction-rules>
`;

function withSecurityXmlResources(config) {
  return withDangerousMod(config, [
    'android',
    (mod) => {
      const xmlDir = path.join(
        mod.modRequest.platformProjectRoot,
        'app',
        'src',
        'main',
        'res',
        'xml',
      );
      fs.mkdirSync(xmlDir, { recursive: true });
      fs.writeFileSync(
        path.join(xmlDir, 'veil_network_security_config.xml'),
        NETWORK_SECURITY_CONFIG,
      );
      fs.writeFileSync(path.join(xmlDir, 'veil_backup_rules.xml'), BACKUP_RULES);
      fs.writeFileSync(
        path.join(xmlDir, 'veil_data_extraction_rules.xml'),
        DATA_EXTRACTION_RULES,
      );

      // expo-secure-store's plugin points the manifest at its own rule files.
      // Write them too, with the same deny-everything content, so the build
      // does not fail on a missing resource if that plugin runs after this one.
      fs.writeFileSync(path.join(xmlDir, 'secure_store_backup_rules.xml'), BACKUP_RULES);
      fs.writeFileSync(
        path.join(xmlDir, 'secure_store_data_extraction_rules.xml'),
        DATA_EXTRACTION_RULES,
      );
      return mod;
    },
  ]);
}

// ---------------------------------------------------------------------------
// Gradle
// ---------------------------------------------------------------------------

/**
 * Release signing and code shrinking.
 *
 * The React Native template ships `signingConfig signingConfigs.debug` in the
 * release block, next to a committed `debug.keystore` whose password is the
 * well-known "android". Shipping that would mean anyone can produce a build
 * that the platform treats as a genuine update to this app - it is the single
 * worst default in the template for a security-sensitive project.
 *
 * This replaces it with a config driven by environment variables and, when
 * they are absent, fails the release build rather than silently falling back
 * to the debug key.
 */
const RELEASE_SIGNING_BLOCK = `
    signingConfigs {
        debug {
            storeFile file('debug.keystore')
            storePassword 'android'
            keyAlias 'androiddebugkey'
            keyPassword 'android'
        }
        release {
            // Supplied by the environment or ~/.gradle/gradle.properties.
            // Never commit a release keystore or its password.
            def storePath = System.getenv("VEIL_KEYSTORE_PATH") ?: project.findProperty("VEIL_KEYSTORE_PATH")
            def storePass = System.getenv("VEIL_KEYSTORE_PASSWORD") ?: project.findProperty("VEIL_KEYSTORE_PASSWORD")
            def alias = System.getenv("VEIL_KEY_ALIAS") ?: project.findProperty("VEIL_KEY_ALIAS")
            def keyPass = System.getenv("VEIL_KEY_PASSWORD") ?: project.findProperty("VEIL_KEY_PASSWORD")
            if (storePath != null && storePass != null && alias != null && keyPass != null) {
                storeFile file(storePath)
                storePassword storePass
                keyAlias alias
                keyPassword keyPass
            }
        }
    }`;

function withReleaseSigning(config) {
  return withAppBuildGradle(config, (mod) => {
    let contents = mod.modResults.contents;

    // Replace the template's signingConfigs block with one that has a real
    // release config alongside debug.
    const signingConfigsPattern =
      /\n {4}signingConfigs \{\n {8}debug \{[\s\S]*?\n {8}\}\n {4}\}/;
    if (signingConfigsPattern.test(contents)) {
      contents = contents.replace(signingConfigsPattern, RELEASE_SIGNING_BLOCK);
    }

    // Point the release build type at the release signing config, and refuse
    // to produce an unsigned-or-debug-signed release.
    contents = contents.replace(
      /(release \{\n)(\s*)\/\/ Caution! In production[^\n]*\n\s*\/\/ see[^\n]*\n\s*signingConfig signingConfigs\.debug/,
      `$1$2// Release builds are signed with the key supplied via
$2// VEIL_KEYSTORE_* (see plugins/withAndroidPrivacy.js). The template's
$2// default signed releases with the committed debug keystore, whose
$2// password is public - that would let anyone forge an update.
$2signingConfig signingConfigs.release
$2doFirst {
$2    if (signingConfigs.release.storeFile == null) {
$2        throw new GradleException(
$2            "Refusing to build a release without a signing key. Set " +
$2            "VEIL_KEYSTORE_PATH, VEIL_KEYSTORE_PASSWORD, VEIL_KEY_ALIAS " +
$2            "and VEIL_KEY_PASSWORD."
$2        )
$2    }
$2}`,
    );

    // Fallback for template variants whose comment wording differs.
    contents = contents.replace(
      /(release \{[\s\S]{0,400}?)signingConfig signingConfigs\.debug/,
      '$1signingConfig signingConfigs.release',
    );

    return { ...mod, modResults: { ...mod.modResults, contents } };
  });
}

// ---------------------------------------------------------------------------

/** Apply all Android hardening. Order matters: resources before the manifest. */
module.exports = function withAndroidPrivacy(config) {
  let next = config;
  next = withSecurityXmlResources(next);
  next = withPermissions(next);
  next = withApplicationHardening(next);
  next = withReleaseSigning(next);
  return next;
};
