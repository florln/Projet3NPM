# COMMANDE D'INSTALLATION.
- installation de notre projet: npm init -y
- ajoutons dans notre projet :
"type": "module" et "dev": "nodemon server.js"

* installation des dependances.
- npm i nodemon -D "en mode developpement"
- npm i express
- npm i socket.io
- npm i cookie-parser
- npm i mongoose
- npm i bcryptjs
- npm i jsonwebtoken

* commande pour lancer le server: "nodemon server.js"
lorsque notre server est lancer sur le port 3000, nous pouvons aller dans URL de postman,
taper les commandes suivantes:
http://localhost:3000/register ajout des utilisateurs.
http://localhost:3000/login connection des utilisateurs
http://localhost:3000/logout deconnection des utilisateurs