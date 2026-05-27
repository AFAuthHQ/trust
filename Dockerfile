FROM node:20-alpine AS builder
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@9.0.0 --activate
COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile=false
COPY tsconfig*.json ./
COPY src ./src
RUN pnpm build

FROM node:20-alpine AS runtime
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@9.0.0 --activate
COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile=false --prod
COPY --from=builder /app/dist ./dist
COPY migrations ./migrations
COPY scripts ./scripts
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "dist/server.js"]
