import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import cookieParser from 'cookie-parser';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import VehicleSimulator from './VehicleSimulator.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const simulator = new VehicleSimulator();
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'bcryptjs';
//Connexion à la base de données MongoDB
mongoose.connect('mongodb://localhost:27017/Projet3npm')
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch((err) => {
        console.error('Error connecting to MongoDB:', err);
    });

//Modèle de l'utilisateur
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

//Middleware pour analyser les requêtes JSON et URL-encoded
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname))); // Serve static files

//Middleware pour vérifier le jeton JWT
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).send('Accès refusé');
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).send('Jeton invalide');
        }
        req.user = user;
        next();
    });
};

//Route pour l'inscription
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Nom d\'utilisateur et mot de passe sont requis');
    }

    if (password.length < 10) {
        return res.status(400).send('Le mot de passe doit contenir au moins 10 caractères');
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const user = new User({ username, password: hashedPassword });
        await user.save();
        res.status(201).send('Utilisateur créé avec succès');
    } catch (error) {
        res.status(500).send('Erreur lors de la création de l\'utilisateur');
    }
});

//Route pour la connexion
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Nom d\'utilisateur et mot de passe sont requis');
    }

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).send('Nom d\'utilisateur ou mot de passe incorrect');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send('Nom d\'utilisateur ou mot de passe incorrect');
        }

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

        //Configure the token in a cookie
        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

        res.json({ message: 'Connexion réussie' });
    } catch (error) {
        res.status(500).send('Erreur lors de la connexion');
    }
});

//Route pour la déconnexion
app.post('/logout', authenticateToken, (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Déconnexion réussie' });
});

//Route sécurisée exemple
app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'Accès autorisé', user: req.user });
});

//Démarrer la simulation
simulator.start();

//Stockage des positions pour accès via l'API
const vehiclePositions = {};

//Écouter les événements de position
simulator.on('position', (data) => {
    const { vehicleId, position, timestamp } = data;
    vehiclePositions[vehicleId] = { position, timestamp };
    console.log(`Position updated for ${vehicleId}: `, position);

    //Envoyer les données de position à tous les clients connectés
    io.emit('position', data);
});

//Écouter les alertes d'immobilité
simulator.on('alert', (data) => {
    const { vehicleId, message } = data;
    console.log(`ALERT: ${message}`);

    //Envoyer les alertes à tous les clients connectés
    io.emit('alert', data);
});

//Route pour récupérer les positions des véhicules
app.get('/positions/:vehicleId', (req, res) => {
    const { vehicleId } = req.params;
    const vehicleData = vehiclePositions[vehicleId];

    if (vehicleData) {
        res.status(200).json(vehicleData);
    } else {
        res.status(404).send('Vehicle not found');
    }
});

//Route pour servir le fichier HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

//Démarrer le serveur
server.listen(PORT, () => {
    console.log(`Serveur en cours d'exécution sur le port ${PORT}`);
});