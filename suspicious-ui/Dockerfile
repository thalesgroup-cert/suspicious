# build
FROM node:alpine AS build
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
