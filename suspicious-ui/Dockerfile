# build
FROM node:alpine AS build
# Proxy build args so npm/pnpm reach the registry through the corporate CONNECT
# proxy (real, trusted cert) instead of a direct — TLS-intercepted — connection.
# Build stage only; the final nginx image does not carry these. Empty by default.
ARG HTTP_PROXY
ARG HTTPS_PROXY
ENV http_proxy=${HTTP_PROXY} \
    https_proxy=${HTTPS_PROXY} \
    HTTP_PROXY=${HTTP_PROXY} \
    HTTPS_PROXY=${HTTPS_PROXY}
WORKDIR /app
RUN npm install -g pnpm@11.1.3

# Reproducible install from the committed pnpm lockfile (pnpm version pinned
# via package.json "packageManager"; workspace file carries dep overrides).
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .
RUN pnpm run build

# run
FROM nginx:alpine
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
COPY docker/docker-entrypoint.sh /docker-entrypoint.d/40-env-config.sh
RUN chmod +x /docker-entrypoint.d/40-env-config.sh
EXPOSE 80
