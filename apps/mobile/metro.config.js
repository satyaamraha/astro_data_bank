/**
 * Metro bundler configuration.
 *
 * The monorepo root must be watched so the app can resolve @veil/crypto and
 * @veil/protocol from the workspace rather than a published copy - the crypto
 * core is developed alongside the app and must never fall out of sync with it.
 */

const path = require('node:path');
const { getDefaultConfig } = require('expo/metro-config');

const projectRoot = __dirname;
const workspaceRoot = path.resolve(projectRoot, '../..');

const config = getDefaultConfig(projectRoot);

config.watchFolders = [workspaceRoot];
config.resolver.nodeModulesPaths = [
  path.resolve(projectRoot, 'node_modules'),
  path.resolve(workspaceRoot, 'node_modules'),
];
config.resolver.disableHierarchicalLookup = true;

module.exports = config;
