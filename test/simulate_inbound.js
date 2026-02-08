const axios = require('axios');

const simulateInbound = async () => {
    try {
        const response = await axios.post('http://localhost:3000/api/inbound', {
            from: 'test@example.com',
            to: 'agent@armourmail.io',
            subject: 'Alpha Test',
            text: 'Hello from the edge.',
            dkim: 'pass',
            SPF: 'pass'
        });
        console.log('Simulation response:', response.status, response.data);
    } catch (error) {
        console.error('Simulation failed:', error.message);
    }
};

simulateInbound();
