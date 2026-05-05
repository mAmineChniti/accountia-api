FROM node:20-bookworm

# Création du dossier de travail
WORKDIR /usr/src/app

# Installation des dépendances système nécessaires pour tes librairies (pdf2pic, sharp, etc.)
RUN apt-get update && apt-get install -y \
    ghostscript \
    graphicsmagick \
    && rm -rf /var/lib/apt/lists/*

# Copie des fichiers de configuration NPM
COPY package*.json ./

# Installation des dépendances Node
RUN npm install --legacy-peer-deps

# Copie du reste du code source
COPY . .

# Compilation du projet NestJS (génère le dossier /dist)
RUN npm run build

# Exposition du port utilisé par l'API
EXPOSE 4789

# Commande de démarrage
CMD ["npm", "run", "start:prod"]
