# Relay image.
#
# Multi-stage so the runtime image carries no compiler, no dev dependencies and
# no source - a smaller image is a smaller attack surface, and there is nothing
# in it worth reading anyway.

FROM node:22-alpine AS build
WORKDIR /build

# Copy manifests first so dependency installation caches independently of
# source changes.
COPY package.json package-lock.json ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/protocol/package.json packages/protocol/
COPY packages/relay/package.json packages/relay/
# The mobile app is not part of the relay build, but npm workspaces needs its
# manifest to resolve the workspace graph.
COPY apps/mobile/package.json apps/mobile/

RUN npm ci --workspace @veil/crypto --workspace @veil/protocol --workspace @veil/relay

COPY tsconfig.base.json ./
COPY packages/crypto packages/crypto
COPY packages/protocol packages/protocol
COPY packages/relay packages/relay

RUN npm run build --workspace @veil/crypto \
 && npm run build --workspace @veil/protocol \
 && npm run build --workspace @veil/relay \
 && npm prune --omit=dev

FROM node:22-alpine AS runtime
WORKDIR /app

# Run unprivileged. The node image ships a `node` user for exactly this.
USER node

COPY --from=build --chown=node:node /build/node_modules ./node_modules
COPY --from=build --chown=node:node /build/packages/crypto/dist ./packages/crypto/dist
COPY --from=build --chown=node:node /build/packages/crypto/package.json ./packages/crypto/
COPY --from=build --chown=node:node /build/packages/protocol/dist ./packages/protocol/dist
COPY --from=build --chown=node:node /build/packages/protocol/package.json ./packages/protocol/
COPY --from=build --chown=node:node /build/packages/relay/dist ./packages/relay/dist
COPY --from=build --chown=node:node /build/packages/relay/package.json ./packages/relay/
COPY --from=build --chown=node:node /build/package.json ./

ENV NODE_ENV=production
EXPOSE 8443

# No healthcheck hitting /v1/health on a timer: it would be the only recurring
# entry in any log, and the container runtime already restarts on exit.
CMD ["node", "packages/relay/dist/server.js"]
