FROM node:20-alpine AS builder
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@9.0.0 --activate
COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile
COPY tsconfig*.json ./
COPY src ./src
RUN pnpm build

FROM node:20-alpine AS runtime
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@9.0.0 --activate
COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile --prod
COPY --from=builder /app/dist ./dist
COPY migrations ./migrations
COPY scripts ./scripts
COPY public ./public
ENV NODE_ENV=production
# Drop root: node:20-alpine ships an unprivileged `node` user. The app
# only reads its bundle and talks to Postgres/Redis over the network — it
# never writes to the image filesystem.
USER node
EXPOSE 3001
CMD ["node", "dist/server.js"]
