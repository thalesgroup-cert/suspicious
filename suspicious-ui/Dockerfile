# build
FROM node:alpine AS build
WORKDIR /app

# Reproducible install from the committed lockfile (matches CI).
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# run
FROM nginx:alpine
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
COPY docker/docker-entrypoint.sh /docker-entrypoint.d/40-env-config.sh
RUN chmod +x /docker-entrypoint.d/40-env-config.sh
EXPOSE 80
