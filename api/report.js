export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).end();

    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'missing url' });

    const redisUrl   = process.env.UPSTASH_REDIS_REST_URL;
    const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;

    if (!redisUrl || !redisToken) {
        return res.status(500).json({ error: 'Redis not configured' });
    }

    try {
        await Promise.all([
            fetch(`${redisUrl}/set/sentinelnet_url/${encodeURIComponent(url)}`, {
                headers: { Authorization: `Bearer ${redisToken}` }
            }),
            fetch(`${redisUrl}/set/sentinelnet_lastseen/${encodeURIComponent(new Date().toISOString())}`, {
                headers: { Authorization: `Bearer ${redisToken}` }
            })
        ]);

        return res.status(200).json({ status: 'ok' });
    } catch (e) {
        return res.status(500).json({ error: e.message });
    }
}