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

