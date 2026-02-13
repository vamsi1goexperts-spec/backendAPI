const https = require('https');

const checkHealth = () => {
    const options = {
        hostname: 'backendapi-h6ch.onrender.com',
        port: 443,
        path: '/health',
        method: 'GET'
    };

    const req = https.request(options, (res) => {
        console.log(`Health Status: ${res.statusCode}`);
        res.on('data', (d) => {
            process.stdout.write(d);
        });
    });

    req.on('error', (e) => {
        console.error(`Health Check Error: ${e.message}`);
    });

    req.end();
};

const checkTokenEndpoint = () => {
    // This expects a 401 because we won't send a token, but it confirms the route exists
    const options = {
        hostname: 'backendapi-h6ch.onrender.com',
        port: 443,
        path: '/api/calls/token',
        method: 'POST'
    };

    const req = https.request(options, (res) => {
        console.log(`\nToken Endpoint Status: ${res.statusCode} (Expected 401)`);
    });

    req.on('error', (e) => {
        console.error(`Token Endpoint Error: ${e.message}`);
    });

    req.end();
};

checkHealth();
setTimeout(checkTokenEndpoint, 2000);
