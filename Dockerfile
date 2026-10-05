FROM node:24-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY src ./src
RUN npm run build:runtime

FROM node:24-alpine AS runtime

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force \
    && apk add --no-cache binutils coreutils dpkg file findutils grep rpm tar

COPY migrations ./migrations
COPY --from=build /app/dist ./dist

ENV NODE_ENV=production
ENV PORT=3001

USER node

EXPOSE 3001
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3001/live').then(r => { if (!r.ok) process.exit(1) }).catch(() => process.exit(1))"

CMD ["node", "dist/index.mjs"]