// ========================================
// TEST FILE 1: WEB APPLICATION VULNERABILITIES
// ========================================

// VULNERABILITY 1: Cross-Site Scripting (XSS) - innerHTML
function displayUserProfile(userData) {
    const profileDiv = document.getElementById('user-profile');
    // CRITICAL: Direct assignment to innerHTML with user data
    profileDiv.innerHTML = userData.name + '<br>' + userData.bio;
}

// VULNERABILITY 2: XSS - document.write
function showWelcomeMessage(username) {
    // CRITICAL: document.write with unsanitized input
    document.write("<h1>Welcome " + username + "</h1>");
}

// VULNERABILITY 3: XSS - eval() usage
function executeUserCode(code) {
    // CRITICAL: eval executes arbitrary JavaScript
    eval(code);
}

// VULNERABILITY 4: Hardcoded API Credentials
const API_CONFIG = {
    apiKey: "sk-1234567890abcdefghijklmnop",
    secretKey: "secret_live_key_9876543210",
    password: "Admin@123!",
    databaseUrl: "mongodb://admin:password123@localhost:27017/mydb"
};

// VULNERABILITY 5: SQL Injection in API call
function getUserById(userId) {
    // CRITICAL: String concatenation in SQL query
    const query = "SELECT * FROM users WHERE id = " + userId;
    return fetch('/api/query', {
        method: 'POST',
        body: JSON.stringify({ sql: query })
    });
}

// VULNERABILITY 6: Command Injection via child_process
const { exec } = require('child_process');

function convertFile(filename) {
    // CRITICAL: Unsanitized user input in system command
    exec('convert ' + filename + ' output.jpg', (error, stdout, stderr) => {
        console.log(stdout);
    });
}

// VULNERABILITY 7: Path Traversal
function readUserFile(filename) {
    const fs = require('fs');
    // CRITICAL: No validation on file path
    return fs.readFileSync('/uploads/' + filename, 'utf8');
}

// VULNERABILITY 8: Insecure Random Number Generation
function generateSessionToken() {
    // CRITICAL: Math.random() is not cryptographically secure
    return Math.random().toString(36).substring(2);
}

// VULNERABILITY 9: Client-Side Authentication
function login(username, password) {
    // CRITICAL: Authentication logic on client side
    if (username === "admin" && password === "admin123") {
        localStorage.setItem('isAuthenticated', 'true');
        localStorage.setItem('role', 'admin');
        return true;
    }
    return false;
}

// VULNERABILITY 10: Insecure Data Storage
function saveUserData(userId, creditCard) {
    // CRITICAL: Storing sensitive data in localStorage
    localStorage.setItem('user_' + userId, JSON.stringify({
        creditCard: creditCard,
        ssn: "123-45-6789"
    }));
}

// ========================================
// TEST FILE 2: NODE.JS SERVER VULNERABILITIES
// ========================================

const express = require('express');
const app = express();

// VULNERABILITY 11: Missing CORS Protection
app.use((req, res, next) => {
    // CRITICAL: Overly permissive CORS
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', '*');
    next();
});

// VULNERABILITY 12: NoSQL Injection
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // CRITICAL: Direct use of user input in MongoDB query
    db.collection('users').findOne({
        username: username,
        password: password
    });
});

// VULNERABILITY 13: Prototype Pollution
function merge(target, source) {
    // CRITICAL: No protection against __proto__ pollution
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// VULNERABILITY 14: Insecure Deserialization
app.post('/import', (req, res) => {
    const data = req.body.serialized;
    // CRITICAL: Using eval to deserialize
    const obj = eval('(' + data + ')');
    processData(obj);
});

// VULNERABILITY 15: Information Disclosure
app.get('/error', (req, res) => {
    try {
        // Some code that might fail
        riskyOperation();
    } catch (error) {
        // CRITICAL: Exposing stack trace to client
        res.status(500).send({
            error: error.message,
            stack: error.stack,
            env: process.env
        });
    }
});

// VULNERABILITY 16: Regex Denial of Service (ReDoS)
app.get('/validate', (req, res) => {
    const email = req.query.email;
    // CRITICAL: Vulnerable regex pattern
    const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    if (emailRegex.test(email)) {
        res.send('Valid');
    }
});

// VULNERABILITY 17: JWT Hardcoded Secret
const jwt = require('jsonwebtoken');

function generateToken(userId) {
    // CRITICAL: Hardcoded JWT secret
    return jwt.sign({ userId: userId }, 'my-secret-key-123', {
        expiresIn: '24h'
    });
}

// VULNERABILITY 18: Weak Password Requirements
function isValidPassword(password) {
    // CRITICAL: No complexity requirements
    return password.length >= 4;
}

// ========================================
// TEST FILE 3: REACT APPLICATION VULNERABILITIES
// ========================================

import React, { useState } from 'react';

// VULNERABILITY 19: XSS in dangerouslySetInnerHTML
function CommentComponent({ comment }) {
    // CRITICAL: Rendering user content without sanitization
    return (
        <div dangerouslySetInnerHTML={{ __html: comment.text }} />
    );
}

// VULNERABILITY 20: Exposed Secrets in Frontend
const config = {
    // CRITICAL: API keys in frontend code
    STRIPE_SECRET_KEY: 'sk_live_51234567890abcdef',
    AWS_ACCESS_KEY: 'AKIAIOSFODNN7EXAMPLE',
    AWS_SECRET_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    DATABASE_URL: 'postgresql://user:pass@localhost/db'
};

// VULNERABILITY 21: Insecure State Management
function UserDashboard() {
    // CRITICAL: Storing sensitive data in component state
    const [userData, setUserData] = useState({
        creditCard: '4532-1234-5678-9010',
        cvv: '123',
        ssn: '123-45-6789'
    });
    
    return <div>{userData.creditCard}</div>;
}

// VULNERABILITY 22: Open Redirect
function RedirectComponent() {
    const urlParams = new URLSearchParams(window.location.search);
    const redirectUrl = urlParams.get('redirect');
    
    // CRITICAL: No validation on redirect URL
    window.location.href = redirectUrl;
}

// ========================================
// TEST FILE 4: AJAX & API VULNERABILITIES
// ========================================

// VULNERABILITY 23: Insecure XMLHttpRequest
function fetchUserData(userId) {
    const xhr = new XMLHttpRequest();
    // CRITICAL: No CSRF protection
    xhr.open('POST', '/api/user/' + userId, true);
    xhr.send();
}

// VULNERABILITY 24: Exposed Admin Endpoint
async function deleteUser(userId) {
    // CRITICAL: Client-side access to admin function
    const response = await fetch('/api/admin/delete/' + userId, {
        method: 'DELETE'
    });
    return response.json();
}

// VULNERABILITY 25: Missing Input Validation
function processPayment(amount, cardNumber) {
    // CRITICAL: No validation on amount or card
    return fetch('/api/payment', {
        method: 'POST',
        body: JSON.stringify({
            amount: amount,
            card: cardNumber
        })
    });
}

// ========================================
// TEST FILE 5: CRYPTOGRAPHY VULNERABILITIES
// ========================================

const crypto = require('crypto');

// VULNERABILITY 26: Weak Encryption Algorithm
function encryptData(data) {
    // CRITICAL: Using deprecated DES algorithm
    const cipher = crypto.createCipher('des', 'weak-key');
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// VULNERABILITY 27: Hardcoded Encryption Key
const ENCRYPTION_KEY = '12345678901234567890123456789012';
const IV = '1234567890123456';

function encryptSensitiveData(text) {
    // CRITICAL: Hardcoded key and IV
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
    return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

// VULNERABILITY 28: Insecure Hash Function
function hashPassword(password) {
    // CRITICAL: Using MD5 without salt
    return crypto.createHash('md5').update(password).digest('hex');
}

// ========================================
// TEST FILE 6: MIXED CRITICAL VULNERABILITIES
// ========================================

// VULNERABILITY 29: Race Condition
let balance = 1000;

async function withdraw(amount) {
    // CRITICAL: No locking mechanism
    if (balance >= amount) {
        await new Promise(resolve => setTimeout(resolve, 100));
        balance -= amount;
        return true;
    }
    return false;
}

// VULNERABILITY 30: Server-Side Request Forgery (SSRF)
app.get('/fetch-url', async (req, res) => {
    const url = req.query.url;
    // CRITICAL: No URL validation
    const response = await fetch(url);
    const data = await response.text();
    res.send(data);
});

// VULNERABILITY 31: Mass Assignment
app.post('/update-profile', (req, res) => {
    const userId = req.user.id;
    // CRITICAL: Allowing all fields to be updated
    User.findByIdAndUpdate(userId, req.body);
});

// VULNERABILITY 32: Insecure File Upload
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

app.post('/upload', upload.single('file'), (req, res) => {
    // CRITICAL: No file type validation
    const file = req.file;
    res.send('File uploaded: ' + file.originalname);
});

// VULNERABILITY 33: Cookie Security Issues
app.get('/set-session', (req, res) => {
    // CRITICAL: Cookie without secure flags
    res.cookie('session', generateSessionToken(), {
        httpOnly: false,
        secure: false,
        sameSite: 'none'
    });
});

// VULNERABILITY 34: XML External Entity (XXE)
const xml2js = require('xml2js');

app.post('/parse-xml', (req, res) => {
    const xmlData = req.body.xml;
    // CRITICAL: XML parser without XXE protection
    xml2js.parseString(xmlData, (err, result) => {
        res.json(result);
    });
});

// VULNERABILITY 35: Integer Overflow
function calculateTotal(price, quantity) {
    // CRITICAL: No bounds checking
    return price * quantity;
}

// ========================================
// TEST FILE 7: AUTHENTICATION BYPASS
// ========================================

// VULNERABILITY 36: Weak Session Management
const sessions = {};

function createSession(userId) {
    // CRITICAL: Predictable session ID
    const sessionId = userId + '_' + Date.now();
    sessions[sessionId] = { userId, timestamp: Date.now() };
    return sessionId;
}

// VULNERABILITY 37: No Rate Limiting
app.post('/login-attempt', async (req, res) => {
    const { username, password } = req.body;
    // CRITICAL: No rate limiting on login attempts
    const user = await User.findOne({ username, password });
    if (user) {
        res.json({ success: true });
    } else {
        res.status(401).json({ success: false });
    }
});

// VULNERABILITY 38: Insecure Password Reset
function resetPassword(email) {
    // CRITICAL: Predictable reset token
    const resetToken = Buffer.from(email + Date.now()).toString('base64');
    sendEmail(email, 'Reset link: /reset?token=' + resetToken);
}

// VULNERABILITY 39: Missing Authorization Check
app.delete('/api/posts/:id', (req, res) => {
    const postId = req.params.id;
    // CRITICAL: No check if user owns the post
    Post.findByIdAndDelete(postId);
    res.send('Deleted');
});

// VULNERABILITY 40: Timing Attack
function comparePasswords(inputPassword, storedPassword) {
    // CRITICAL: Non-constant time comparison
    return inputPassword === storedPassword;
}

// ========================================
// EXPECTED VULNERABILITIES SUMMARY
// ========================================

/*
CRITICAL VULNERABILITIES (Should be detected):
1. XSS via innerHTML (3 instances)
2. XSS via document.write
3. XSS via eval
4. Hardcoded credentials (5 instances)
5. SQL Injection
6. Command Injection
7. Path Traversal
8. Insecure Random Generation
9. Client-Side Authentication
10. Insecure Data Storage
11. CORS Misconfiguration
12. NoSQL Injection
13. Prototype Pollution
14. Insecure Deserialization
15. Information Disclosure
16. ReDoS
17. JWT Hardcoded Secret
18. Weak Password Policy
19. dangerouslySetInnerHTML
20. Exposed API Keys in Frontend
21. Sensitive Data in State
22. Open Redirect
23. Missing CSRF Protection
24. Exposed Admin Endpoints
25. Missing Input Validation
26. Weak Encryption (DES)
27. Hardcoded Encryption Keys
28. Weak Hash (MD5)
29. Race Condition
30. SSRF
31. Mass Assignment
32. Insecure File Upload
33. Insecure Cookies
34. XXE
35. Integer Overflow
36. Weak Session Management
37. No Rate Limiting
38. Insecure Password Reset
39. Missing Authorization
40. Timing Attack

Total: 40+ distinct vulnerabilities across 8 categories
*/