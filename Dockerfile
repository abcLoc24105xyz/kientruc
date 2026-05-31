FROM node:20-alpine

WORKDIR /app

ARG SERVICE_PATH

COPY ${SERVICE_PATH}/package*.json ./

RUN npm install

COPY ${SERVICE_PATH}/ ./

ENV NODE_ENV=production

EXPOSE 3000

CMD ["node", "server.js"]