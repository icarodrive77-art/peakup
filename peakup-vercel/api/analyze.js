// Rate limiting simple en mémoire (reset au redéploiement)
const rateLimit = new Map();
const RATE_WINDOW = 60 * 1000; // 1 minute
const RATE_MAX = 5; // 5 analyses par minute par IP

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Rate limiting par IP
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
  const now = Date.now();
  const record = rateLimit.get(ip) || { count: 0, start: now };
  if (now - record.start > RATE_WINDOW) {
    record.count = 0;
    record.start = now;
  }
  record.count++;
  rateLimit.set(ip, record);
  if (record.count > RATE_MAX) {
    return res.status(429).json({ error: 'Trop de requêtes. Réessaie dans une minute.' });
  }

  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: 'Missing prompt' });
  if (prompt.length > 2000) return res.status(400).json({ error: 'Prompt trop long' });

  const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    const data = await response.json();
    const text = data.content ? data.content.map(b => b.text || '').join('\n') : '';
    res.status(200).json({ text });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}
