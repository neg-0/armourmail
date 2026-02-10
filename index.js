require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const upload = multer();

const app = express();
const PORT = process.env.PORT || 3001;

app.get('/health', (req, res) => res.send('OK'));

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Logger
app.use((req, res, next) => {
    console.log(`[REQUEST] ${req.method} ${req.url}`);
    next();
});

const fs = require('fs');
const path = require('path');

// SendGrid Inbound Parse Webhook
app.post('/api/inbound', upload.any(), (req, res) => {
    try {
        const { from, to, subject, text, html, envelope, dkim, SPF } = req.body;
        const parsedEnvelope = envelope ? JSON.parse(envelope) : {};

        // Routing config (v0)
        const agentsConfigPath = path.join(__dirname, 'config', 'agents.json');
        const agentsConfig = fs.existsSync(agentsConfigPath)
            ? JSON.parse(fs.readFileSync(agentsConfigPath, 'utf8'))
            : { agents: {} };

        const envelopeTo = Array.isArray(parsedEnvelope?.to) ? parsedEnvelope.to : [];
        const recipient = (envelopeTo[0] || to || '').toString().trim().toLowerCase();
        const routedAgent = recipient ? agentsConfig.agents?.[recipient] : null;

        console.log(`[INBOUND] From: ${from}, To: ${to}, Subject: ${subject}`);
        console.log(`[ROUTER] recipient=${recipient || '(none)'} agent=${routedAgent ? routedAgent.id : '(unmapped)'}`);

        // Security Check: Basic SPF/DKIM validation
        const isAuthentic = (dkim && dkim.includes('pass')) || (SPF && SPF.includes('pass'));
        if (!isAuthentic) {
            console.warn(`[SECURITY] Potential spoofed email from ${from}`);
            // In Alpha, we might still log but flag it
        }

        // Log the inbound request for audit
        const logEntry = {
            timestamp: new Date().toISOString(),
            from,
            to,
            subject,
            envelope: parsedEnvelope,
            isAuthentic,
            recipient,
            routedAgent: routedAgent ? { id: routedAgent.id, sessionKey: routedAgent.sessionKey } : null,
            textSnippet: text ? text.substring(0, 100) : ''
        };

        const logPath = path.join(__dirname, 'inbound_log.json');
        let logs = [];
        if (fs.existsSync(logPath)) {
            logs = JSON.parse(fs.readFileSync(logPath, 'utf8'));
        }
        logs.push(logEntry);
        fs.writeFileSync(logPath, JSON.stringify(logs.slice(-100), null, 2)); // Keep last 100

        // Next: dispatch to downstream worker / queue

        res.status(200).send('OK');
    } catch (error) {
        console.error('[ERROR] Processing inbound email:', error);
        res.status(500).send(`Internal Server Error: ${error.message}`);
    }
});

app.listen(PORT, () => {
    console.log(`ArmourMail Warden active on port ${PORT}`);
});
