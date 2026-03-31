# build
FROM node:alpine AS build
WORKDIR /app

# Install pnpm without corepack
RUN npm install -g pnpm@latest --no-corepack

COPY package.json ./
RUN pnpm install

COPY . .
RUN pnpm build

# run
FROM nginx:alpine
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
