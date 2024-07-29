import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import crypto from 'crypto';

const app = express();

app.use(cors());
app.use(express.json());

app.use('/api', async (req, res) => {
    const url = 'http://10.176.12.148' + req.url; // Base URL for the API
    console.log('Proxying request to:', url);

    let response = await fetch(url, {
        method: req.method,
        headers: req.headers,
        body: req.method === 'POST' ? JSON.stringify(req.body) : undefined
    });

    if (response.status === 401 && response.headers.get('www-authenticate')) {
        const authHeader = response.headers.get('www-authenticate');
        const authDetails = parseDigestAuth(authHeader, 'vivek', 'kumar', req.method, req.url);

        response = await fetch(url, {
            method: req.method,
            headers: {
                ...req.headers,
                'Authorization': authDetails,
                'Content-Type': req.headers['content-type'] || 'application/json'
            },
            body: req.method === 'POST' ? JSON.stringify(req.body) : undefined
        });
    }

    res.status(response.status);
    response.body.pipe(res);
});

function parseDigestAuth(authHeader, username, password, method, uri) {
    const authDetails = {};
    const nc = '00000001'; // Nonce count
    const cnonce = crypto.randomBytes(8).toString('hex'); // Client nonce

    authHeader.replace(/([a-z0-9_-]+)="?([^",]+)"?/gi, (match, key, value) => {
        authDetails[key] = value;
    });

    const ha1 = md5(`${username}:${authDetails.realm}:${password}`);
    const ha2 = md5(`${method}:${uri}`);
    const response = md5(`${ha1}:${authDetails.nonce}:${nc}:${cnonce}:${authDetails.qop}:${ha2}`);

    return `Digest username="${username}", realm="${authDetails.realm}", nonce="${authDetails.nonce}", uri="${uri}", qop=${authDetails.qop}, nc=${nc}, cnonce="${cnonce}", response="${response}"`;
}

function md5(input) {
    return crypto.createHash('md5').update(input).digest('hex');
}

const port = 3000;
app.listen(port, () => {
    console.log(`Proxy server is running on http://localhost:${port}`);
});
