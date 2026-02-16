require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const upload = multer();
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const axios = require('axios');

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

// Helper function to scan text
function scanText(text) {
    return new Promise((resolve, reject) => {
        const pythonProcess = spawn('python3', [path.join(__dirname, 'detector.py')]);
        let output = '';
        let error = '';

        pythonProcess.stdout.on('data', (data) => {
            output += data.toString();
        });

        pythonProcess.stderr.on('data', (data) => {
            error += data.toString();
        });

        pythonProcess.on('close', (code) => {
            if (code !== 0) {
                // If the process exits with non-zero, it might be an error or just handled in script
                if (output) {
                     try {
                        resolve(JSON.parse(output));
                    } catch (e) {
                         reject(new Error(`Detector failed with code ${code}: ${error}`));
                    }
                } else {
                    reject(new Error(`Detector failed with code ${code}: ${error}`));
                }
            } else {
                try {
                    resolve(JSON.parse(output));
                } catch (e) {
                    reject(new Error(`Failed to parse detector output: ${e.message}`));
                }
            }
        });

        pythonProcess.stdin.write(text || '');
        pythonProcess.stdin.end();
    });
}

// SendGrid Inbound Parse Webhook
app.post('/api/inbound', upload.any(), async (req, res) => {
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

        // --- NEW: Detector Scan ---
        let detectionResult = { detected: false, matches: [], score: 0 };
        try {
            const contentToScan = (subject || '') + '\n' + (text || '') + '\n' + (html || ''); // Simple concat
            detectionResult = await scanText(contentToScan);
            if (detectionResult.detected) {
                console.warn(`[SECURITY] Prompt Injection Detected! Score: ${detectionResult.score}, Matches: ${JSON.stringify(detectionResult.matches)}`);
            }
        } catch (scanError) {
            console.error('[SECURITY] Detector failed:', scanError);
        }
        // --------------------------

        // Log the inbound request for audit
        const logEntry = {
            timestamp: new Date().toISOString(),
            from,
            to,
            subject,
            envelope: parsedEnvelope,
            isAuthentic,
            detection: detectionResult, // Added detection result
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

        if (routedAgent && process.env.OPENCLAW_HOOKS_TOKEN) {
            try {
                const gatewayUrl = process.env.OPENCLAW_GATEWAY_URL || 'http://localhost:18789';
                const hooksToken = process.env.OPENCLAW_HOOKS_TOKEN;

                const emailBody = text || html || '(No content)';
                // Limit body size to avoid huge payloads
                const truncatedBody = emailBody.length > 5000 ? emailBody.substring(0, 5000) + '... (truncated)' : emailBody;
                
                const agentMessage = `📧 New Email Received\nFrom: ${from}\nTo: ${to}\nSubject: ${subject}\n\n${truncatedBody}`;

                console.log(`[DISPATCH] Forwarding to ${routedAgent.id}...`);
                
                await axios.post(`${gatewayUrl}/hooks/agent`, {
                    message: agentMessage,
                    name: "Email",
                    agentId: routedAgent.id,
                    wakeMode: "now",
                    deliver: true
                }, {
                    headers: {
                        'Authorization': `Bearer ${hooksToken}`,
                        'Content-Type': 'application/json'
                    }
                });
                
                console.log(`[DISPATCH] Successfully sent to ${routedAgent.id}`);
            } catch (dispatchError) {
                console.error('[ERROR] Failed to dispatch to agent:', dispatchError.message);
                if (dispatchError.response) {
                    console.error('[ERROR] Gateway response:', JSON.stringify(dispatchError.response.data));
                }
            }
        } else {
             if (routedAgent) console.warn('[CONFIG] OPENCLAW_HOOKS_TOKEN missing, skipping dispatch.');
        }

        res.status(200).send('OK');
    } catch (error) {
        console.error('[ERROR] Processing inbound email:', error);
        res.status(500).send(`Internal Server Error: ${error.message}`);
    }
});

app.listen(PORT, () => {
    console.log(`ArmourMail Warden active on port ${PORT}`);
});
