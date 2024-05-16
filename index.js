const express = require('express');
const rateLimit = require("express-rate-limit");
const mongoose = require("mongoose");
const moment = require("moment-timezone");

// Connect to MongoDB
mongoose.connect(process.env.DB_URL);
const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));
db.once("open", function () {
    console.log("Connected to MongoDB");
});

// Create a schema for storing IP addresses
const ipSchema = new mongoose.Schema({
    ip: String,
    timestamp: {
        type: Date,
        default: Date.now
    }
});

const IP = mongoose.model("IP", ipSchema);

// Create a schema for banned IPs
const bannedIpSchema = new mongoose.Schema({
    ip: String,
    timestamp: {
        type: Date,
        default: Date.now
    }
});

const BannedIP = mongoose.model("BannedIP", bannedIpSchema);

const limiter = rateLimit({
    windowMs: 1000, // 1 second
    max: 5, // limit each IP to 5 requests per windowMs
    handler: async (req, res, next) => {
        try {
            // Check if the IP is banned
            const isBanned = await BannedIP.exists({ ip: req.ip });
            if (isBanned) {
                return res.status(403).json({ error: 'You are banned. Please contact support for further assistance.' });
            }

            // Check if the IP has exceeded the limit more than 5 times
            const count = await IP.countDocuments({ ip: req.ip, timestamp: { $gt: new Date(Date.now() - 60000) } });
            if (count > 4) {
                // Ban the IP
                await BannedIP.create({ ip: req.ip });
                return res.status(403).json({ error: 'You are banned. Please contact support for further assistance.' });
            }

            // Store the IP address in MongoDB with user's timezone
            const userTimezone = req.headers['timezone'] || 'UTC'; // Default to UTC if timezone is not provided
            const timestamp = moment().tz(userTimezone).format();
            await IP.create({ ip: req.ip, timestamp });

            return res.status(429).json({ error: 'Too many requests from this IP, please try again later' });
        } catch (err) {
            next(err);
        }
    }
});

// Check if the IP is banned
const checkBan = async (req, res, next) => {
    try {
        const isBanned = await BannedIP.exists({ ip: req.ip });
        if (isBanned) {
            return res.status(403).json({ error: 'You are banned. Please contact support for further assistance.' });
        }
        next();
    } catch (err) {
        next(err);
    }
};

const app = express();

// Enable trust proxy
app.set('trust proxy', 1);

// Apply the ban check middleware to all requests
app.use(checkBan);

// Apply the rate limiter to all requests
app.use(limiter);

app.get("/", (req, res) => {
    res.send("Hello World! your ip is " + req.ip);
});

app.listen(process.env.PORT || 3000, () => {
    console.log("Server is running on port 3000");
});
