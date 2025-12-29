FROM node:20-bullseye-slim AS builder

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install

COPY . ./
RUN npm run typecheck && npm test && npm run build

FROM node:20-bullseye-slim

WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./package.json

RUN mkdir -p /data \
  && chown -R node:node /app /data

USER node

ENV NODE_ENV=production \
  PORT=3000 \
  DB_PATH=/data/provisioning.db

EXPOSE 3000

CMD ["node", "dist/server/index.js"]
