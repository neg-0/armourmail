const simulateInbound = async () => {
    try {
        const url = 'http://127.0.0.1:3001/api/inbound';
        console.log(`Sending multipart request to ${url}`);

        // Node 18+ provides global FormData + fetch
        const form = new FormData();
        form.append('from', 'test@example.com');
        form.append('to', 'warden@armourmail.io');
        form.append('subject', 'Alpha Test');
        form.append('text', 'Hello from the edge.');
        form.append('envelope', JSON.stringify({ to: ['warden@armourmail.io'], from: 'test@example.com' }));
        form.append('dkim', 'pass');
        form.append('SPF', 'pass');

        const res = await fetch(url, { method: 'POST', body: form });
        const body = await res.text();
        console.log('Simulation response:', res.status, body);
    } catch (error) {
        console.error('Simulation failed:', error);
    }
};

simulateInbound();
