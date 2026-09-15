FROM node:22.20.0-alpine3.22 AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:1.27.5-alpine3.21-slim
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/default.conf.template
COPY --chmod=755 docker-entrypoint.sh /usr/local/bin/t3-privacy-frontend-entrypoint
EXPOSE 80
CMD ["/usr/local/bin/t3-privacy-frontend-entrypoint"]
