/**
 * Expo entry point.
 *
 * Deployment configuration lives here so the relay and ICE servers are an
 * explicit deployment choice rather than something baked into the app. Point
 * these at infrastructure you control: the relay cannot read your messages
 * either way, but it does see recipient addresses and connection IPs.
 */

import { registerRootComponent } from 'expo';
import { App } from './src/App';

const config = {
  relayHttpUrl: process.env.EXPO_PUBLIC_VEIL_RELAY_HTTP ?? 'https://localhost:8443',
  relaySocketUrl: process.env.EXPO_PUBLIC_VEIL_RELAY_WS ?? 'wss://localhost:8443/v1/socket',
  ice: {
    iceServers: [{ urls: process.env.EXPO_PUBLIC_VEIL_STUN ?? 'stun:localhost:3478' }],
    // Forcing relay mode hides both peers' IP addresses from each other. Safe
    // for confidentiality because SFrame means the TURN server still cannot
    // hear the call; costs latency, so it is opt-in.
    relayOnly: process.env.EXPO_PUBLIC_VEIL_RELAY_ONLY === 'true',
  },
};

function Root() {
  return App({ config });
}

registerRootComponent(Root);
