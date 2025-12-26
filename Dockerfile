FROM node:20-bullseye-slim

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev

COPY . ./

RUN mkdir -p /data \
  && chown -R node:node /app /data

USER node

ENV NODE_ENV=production \
  PORT=3000 \
  DB_PATH=/data/provisioning.db

EXPOSE 3000

CMD ["node", "server/index.js"]
