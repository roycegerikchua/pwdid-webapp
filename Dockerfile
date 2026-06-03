FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev
COPY server.js ./server.js
COPY public ./public
COPY scripts ./scripts
EXPOSE 3015
CMD ["node", "server.js"]
