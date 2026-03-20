export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();

    const redisUrl   = process.env.UPSTASH_REDIS_REST_URL;
    const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;

    if (!redisUrl || !redisToken) {
        return res.status(500).json({ error: 'Redis not configured' });
    }

    if (req.method === 'POST') {
        const { command, target } = req.body;
        if (!command) return res.status(400).json({ error: 'missing command' });

        const task = JSON.stringify({ command, target, timestamp: new Date().toISOString() });

        try {
            await fetch(`${redisUrl}/set/sentinelnet_task/${encodeURIComponent(task)}`, {
                headers: { Authorization: `Bearer ${redisToken}` }
            });
            return res.status(200).json({ status: 'ok', task });
        } catch (e) {
            return res.status(500).json({ error: e.message });
        }
    }

    if (req.method === 'GET') {
        try {
            const resp = await fetch(`${redisUrl}/get/sentinelnet_task`, {
                headers: { Authorization: `Bearer ${redisToken}` }
            });
            const data = await resp.json();
            const task = data.result ? JSON.parse(data.result) : null;
            return res.status(200).json({ task });
        } catch (e) {
            return res.status(200).json({ task: null });
        }
    }

    return res.status(405).end();
}
