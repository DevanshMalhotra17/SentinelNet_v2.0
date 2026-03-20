export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();

    const redisUrl   = process.env.UPSTASH_REDIS_REST_URL;
    const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;

    if (!redisUrl || !redisToken) {
        return res.status(200).json({ url: 'offline', lastSeen: null, error: 'Redis not configured' });
    }

    try {
        const [urlResp, timeResp, taskResp] = await Promise.all([
            fetch(`${redisUrl}/get/sentinelnet_url`, {
                headers: { Authorization: `Bearer ${redisToken}` }
            }),
            fetch(`${redisUrl}/get/sentinelnet_lastseen`, {
                headers: { Authorization: `Bearer ${redisToken}` }
            }),
            fetch(`${redisUrl}/get/sentinelnet_task`, {
                headers: { Authorization: `Bearer ${redisToken}` }
            })
        ]);

        const urlData  = await urlResp.json();
        const timeData = await timeResp.json();
        const taskData = await taskResp.json();

        const url      = urlData.result  || 'offline';
        const lastSeen = timeData.result || null;
        const task     = taskData.result ? JSON.parse(taskData.result) : null;

        return res.status(200).json({ url, lastSeen, task });
    } catch (e) {
        return res.status(200).json({ url: 'offline', lastSeen: null, error: e.message });
    }
}