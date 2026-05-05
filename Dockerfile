FROM node:20-bookworm-slim AS base

WORKDIR /usr/src/app

ENV npm_config_fund=false \
    npm_config_update_notifier=false

FROM base AS deps

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    g++ \
    make \
    ghostscript \
    graphicsmagick \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./

RUN npm i --legacy-peer-deps

FROM base AS build

COPY --from=deps /usr/src/app/node_modules ./node_modules
COPY . .

RUN npm run build \
    && npm cache clean --force

FROM node:20-bookworm-slim AS runtime

WORKDIR /usr/src/app

ENV NODE_ENV=production \
    PORT=4789 \
    npm_config_fund=false \
    npm_config_update_notifier=false

RUN apt-get update && apt-get install -y --no-install-recommends \
    ghostscript \
    graphicsmagick \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build --chown=node:node /usr/src/app/node_modules ./node_modules
COPY --from=build --chown=node:node /usr/src/app/dist ./dist

USER node

EXPOSE 4789

CMD ["node", "dist/main.js"]
