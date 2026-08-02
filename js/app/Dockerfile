FROM node:24-bookworm-slim AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG LLM_NOTARY_PUBLIC_ORIGIN=https://llm-notary.exalto.ai
ENV VITE_PUBLIC_ORIGIN=$LLM_NOTARY_PUBLIC_ORIGIN
RUN npm run build:site

FROM caddy:2.10-alpine

COPY Caddyfile /etc/caddy/Caddyfile
COPY --from=builder /app/dist /usr/share/caddy

EXPOSE 80 443
