# syntax=docker/dockerfile:1.6
FROM node:20-bullseye-slim AS builder

WORKDIR /app

RUN --mount=type=cache,target=/var/cache/apt \
  --mount=type=cache,target=/var/lib/apt \
  apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci

COPY . ./
RUN npm run typecheck && npm test && npm run build \
  && npm prune --omit=dev

FROM node:20-bullseye-slim

WORKDIR /app

COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --from=builder --chown=node:node /app/dist ./dist
COPY --from=builder --chown=node:node /app/public ./public
COPY --from=builder --chown=node:node /app/package.json ./package.json

RUN mkdir -p /data \
  && chown -R node:node /data

USER node

ENV NODE_ENV=production \
  PORT=3000 \
  DB_PATH=/data/provisioning.db

EXPOSE 3000

CMD ["node", "dist/server/index.js"]
