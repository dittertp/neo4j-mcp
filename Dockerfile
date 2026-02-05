# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Abhängigkeiten kopieren
COPY package.json package-lock.json ./

# Alle Abhängigkeiten installieren
RUN npm install

# Quellcode kopieren
COPY tsconfig.json ./
COPY src/ ./src/

# TypeScript kompilieren
RUN npm run build

# Stage 2: Run
FROM node:20-alpine

WORKDIR /app

# Nur produktive Abhängigkeiten kopieren und installieren
COPY package.json package-lock.json ./
RUN npm install --production

# Kompilierten Code aus der Builder-Stage kopieren
COPY --from=builder /app/build ./build

# Port exponieren
EXPOSE 3000

# Server starten
CMD ["node", "build/index.js"]
