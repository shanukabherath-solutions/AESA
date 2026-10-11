
FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY --chown=node:node . .
RUN chown -R node:node /app

USER node

EXPOSE 5173

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
