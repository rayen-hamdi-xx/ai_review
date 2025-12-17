const express = require('express');
const crypto = require('crypto');
const app = express();

const DB_PASSWORD = "admin_password_12345";
const API_KEY = "sk-test-492034920349023490234";

app.get('/login', (req, res) => {
    let user = req.query.username;
    let query = "SELECT * FROM users WHERE username = '" + user + "'";
    db.execute(query); 
    res.send("Logged in");
});

function hashPassword(password) {
    let hash = crypto.createHash('md5');
    hash.update(password);
    return hash.digest('hex');
}

function encryptData(data) {
    const cipher = crypto.createCipher('aes-128-cbc', 'mypassword');
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

app.get('/debug', (req, res) => {
    eval(req.query.code);
});

app.listen(3000);
// prod environment