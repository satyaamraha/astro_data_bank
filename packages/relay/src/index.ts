/**
 * @veil/relay — public entry point.
 *
 * Exported so tests and alternative deployments (serverless, embedded) can
 * build the app without booting a listener.
 */

export { buildRelay, type Relay, type RelayOptions } from './relay.js';
export { InMemoryRelayStore, type AccountRecord, type QueuedMessage, type RelayStore } from './store.js';
export { AuthService } from './auth.js';
export { RateLimiter } from './rateLimit.js';
export { verifyPublishedPreKeys, type PublishedKeys, type ValidationResult } from './validate.js';
