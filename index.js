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

// Admin Authentication Middleware
const authenticateAdmin = (req, res, next) => {
    const apiKey = req.headers['x-admin-api-key'];
    if (!apiKey || apiKey !== process.env.ADMIN_API_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
};

// Admin Routes
app.get('/admin/agents', authenticateAdmin, (req, res) => {
    try {
        const agentsConfigPath = path.join(__dirname, 'config', 'agents.json');
        if (!fs.existsSync(agentsConfigPath)) {
            return res.json({ agents: {} });
        }
        const config = JSON.parse(fs.readFileSync(agentsConfigPath, 'utf8'));
        res.json(config);
    } catch (error) {
        res.status(500).json({ error: 'Failed to read agent config' });
    }
});

app.post('/admin/agents', authenticateAdmin, (req, res) => {
    try {
        const { email, agentId, sessionKey, description, webhookUrl } = req.body;
        
        if (!email || !agentId) {
            return res.status(400).json({ error: 'Missing required fields: email, agentId' });
        }

        const agentsConfigPath = path.join(__dirname, 'config', 'agents.json');
        let config = { agents: {} };
        
        if (fs.existsSync(agentsConfigPath)) {
            config = JSON.parse(fs.readFileSync(agentsConfigPath, 'utf8'));
        }

        config.agents[email] = {
            id: agentId,
            sessionKey: sessionKey || `agent:${agentId}:main`,
            description: description || '',
            webhookUrl: webhookUrl || null
        };

        fs.writeFileSync(agentsConfigPath, JSON.stringify(config, null, 2));
        
        console.log(`[ADMIN] Registered agent: ${email} -> ${agentId}`);
        res.json({ success: true, agent: config.agents[email] });
    } catch (error) {
        console.error('[ADMIN] Failed to register agent:', error);
        res.status(500).json({ error: 'Failed to update agent config' });
    }
});

// Dashboard Route
app.get('/dashboard', (req, res) => {
    const apiKey = req.query.key;
    if (!apiKey || apiKey !== process.env.ADMIN_API_KEY) {
        return res.status(401).send('Unauthorized: Invalid Key');
    }

    const logPath = path.join(__dirname, 'inbound_log.json');
    let logs = [];
    if (fs.existsSync(logPath)) {
        try {
            logs = JSON.parse(fs.readFileSync(logPath, 'utf8'));
            if (!Array.isArray(logs)) logs = [];
        } catch (e) {
            logs = [];
        }
    }

    // Sort by newest first
    logs.reverse();

    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>ArmourMail Dashboard</title>
        <style>
            body { font-family: sans-serif; padding: 20px; background-color: #f9f9f9; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; background-color: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
            th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
            th { background-color: #f2f2f2; font-weight: bold; }
            tr:hover { background-color: #f5f5f5; }
            .quarantined { background-color: #ffebee; color: #c62828; }
            .quarantined td { border-color: #ef9a9a; }
            .safe { color: #2e7d32; }
            .status-badge { 
                padding: 4px 8px; 
                border-radius: 4px; 
                font-size: 0.85em; 
                font-weight: bold; 
                text-transform: uppercase;
            }
            .status-quarantined { background-color: #d32f2f; color: white; }
            .status-processed { background-color: #388e3c; color: white; }
        </style>
    </head>
    <body>
        <h1>🛡️ ArmourMail Quarantine Dashboard</h1>
        <p>Viewing ${logs.length} recent emails.</p>
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>From</th>
                    <th>To (Agent)</th>
                    <th>Subject</th>
                    <th>Status</th>
                    <th>Score</th>
                </tr>
            </thead>
            <tbody>
                ${logs.map(log => {
                    const isQuarantined = log.detection && log.detection.detected;
                    const rowClass = isQuarantined ? 'quarantined' : '';
                    const statusBadge = isQuarantined 
                        ? '<span class="status-badge status-quarantined">Quarantined</span>' 
                        : '<span class="status-badge status-processed">Processed</span>';
                    
                    const score = log.detection ? log.detection.score : 0;
                    const agentId = log.routedAgent ? log.routedAgent.id : '<span style="color: #999;">Unmapped</span>';
                    
                    return `
                    <tr class="${rowClass}">
                        <td>${new Date(log.timestamp).toLocaleString()}</td>
                        <td>${log.from}</td>
                        <td>${log.recipient}<br><small>${agentId}</small></td>
                        <td>${log.subject}</td>
                        <td>${statusBadge}</td>
                        <td>${score}</td>
                    </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    </body>
    </html>
    `;
    res.send(html);
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
            try {
                logs = JSON.parse(fs.readFileSync(logPath, 'utf8'));
                if (!Array.isArray(logs)) logs = [];
            } catch (e) {
                logs = [];
            }
        }
        logs.push(logEntry);
        fs.writeFileSync(logPath, JSON.stringify(logs.slice(-100), null, 2)); // Keep last 100

        // Next: dispatch to downstream worker / queue

        // QUARANTINE LOGIC
        if (detectionResult.detected) {
            console.warn(`[QUARANTINE] Email blocked for ${routedAgent ? routedAgent.id : 'unknown'}. Score: ${detectionResult.score}`);
            return res.status(200).send('OK (Quarantined)');
        }

        if (routedAgent) {
            const emailBody = text || html || '(No content)';
            const truncatedBody = emailBody.length > 5000 ? emailBody.substring(0, 5000) + '... (truncated)' : emailBody;

            if (routedAgent.webhookUrl) {
                // Custom Webhook Dispatch
                console.log(`[DISPATCH] Forwarding to custom webhook for ${routedAgent.id}...`);
                try {
                    await axios.post(routedAgent.webhookUrl, {
                        from,
                        to,
                        subject,
                        text,
                        html,
                        agentId: routedAgent.id,
                        detection: detectionResult
                    });
                     console.log(`[DISPATCH] Successfully sent to webhook for ${routedAgent.id}`);
                } catch (err) {
                     console.error('[ERROR] Failed to dispatch to webhook:', err.message);
                }
            } else if (process.env.OPENCLAW_HOOKS_TOKEN) {
                // Default OpenClaw Gateway Dispatch
                try {
                    const gatewayUrl = process.env.OPENCLAW_GATEWAY_URL || 'http://localhost:18789';
                    const hooksToken = process.env.OPENCLAW_HOOKS_TOKEN;

                    const agentMessage = `📧 New Email Received\nFrom: ${from}\nTo: ${to}\nSubject: ${subject}\n\n${truncatedBody}`;

                    console.log(`[DISPATCH] Forwarding to OpenClaw Gateway for ${routedAgent.id}...`);
                    
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
                 console.warn('[CONFIG] No webhookUrl and OPENCLAW_HOOKS_TOKEN missing, skipping dispatch.');
            }
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
