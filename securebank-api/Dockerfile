FROM node:20-alpine

WORKDIR /app

# Install dependencies first (better Docker layer caching)
COPY package.json .
RUN npm install --production

# Copy application code
COPY server.js .
COPY public/ ./public/

EXPOSE 8080

CMD ["node", "server.js"]
