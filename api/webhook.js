import crypto from 'crypto';

// ─── Stripe signature verification ──────────────────────────────────────────

function verifyStripeSignature(rawBody, sigHeader, secret) {
  if (!sigHeader || !secret) return false;
  const parts = Object.fromEntries(
    sigHeader.split(',').map(p => { const i = p.indexOf('='); return [p.slice(0, i), p.slice(i + 1)]; })
  );
  if (!parts.t || !parts.v1) return false;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${parts.t}.${rawBody}`)
    .digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(parts.v1, 'hex'));
  } catch {
    return false;
  }
}

// ─── Google OAuth2 token from service account (no external deps) ────────────

async function getGoogleToken() {
  const email = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
  if (!email || !privateKey) throw new Error('FIREBASE_CLIENT_EMAIL / FIREBASE_PRIVATE_KEY not set');

  const now = Math.floor(Date.now() / 1000);
  const header  = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: email, sub: email,
    aud: 'https://oauth2.googleapis.com/token',
    iat: now, exp: now + 3600,
    scope: 'https://www.googleapis.com/auth/datastore',
  })).toString('base64url');

  const sign = crypto.createSign('RSA-SHA256');
  sign.update(`${header}.${payload}`);
  const signature = sign.sign(privateKey, 'base64url');
  const jwt = `${header}.${payload}.${signature}`;

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });
  const data = await res.json();
  if (!data.access_token) throw new Error('Google token error: ' + JSON.stringify(data));
  return data.access_token;
}

// ─── Firestore REST helpers ──────────────────────────────────────────────────

const PROJECT_ID = process.env.FIREBASE_PROJECT_ID || 'peakup-2070a';
const FS = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents`;

async function fsSet(collection, docId, fields, token) {
  const url = `${FS}/${collection}/${encodeURIComponent(docId)}`;
  const res = await fetch(url, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields }),
  });
  if (!res.ok) throw new Error(`Firestore PATCH ${collection}/${docId} → ${res.status}: ${await res.text()}`);
}

async function fsGet(collection, docId, token) {
  const url = `${FS}/${collection}/${encodeURIComponent(docId)}`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`Firestore GET ${collection}/${docId} → ${res.status}`);
  return res.json();
}

// ─── Raw body reader (needed before Vercel parses the body) ─────────────────

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// ─── Handler ─────────────────────────────────────────────────────────────────

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!webhookSecret) return res.status(500).json({ error: 'STRIPE_WEBHOOK_SECRET not configured' });

  const rawBody = await getRawBody(req);
  if (!verifyStripeSignature(rawBody, req.headers['stripe-signature'], webhookSecret)) {
    return res.status(400).json({ error: 'Invalid Stripe signature' });
  }

  const event = JSON.parse(rawBody);

  try {
    const token = await getGoogleToken();

    switch (event.type) {

      // Nouveau paiement : activer Pro et créer le mapping customer → uid
      case 'checkout.session.completed': {
        const session = event.data.object;
        const uid = session.metadata?.firebaseUid;
        const customerId = session.customer;
        if (!uid) break;
        await fsSet('users', uid, {
          isPro: { booleanValue: true },
          stripeCustomerId: { stringValue: customerId || '' },
        }, token);
        if (customerId) {
          await fsSet('stripe_customers', customerId, { uid: { stringValue: uid } }, token);
        }
        break;
      }

      // Renouvellement réussi : confirmer isPro (au cas où il avait été suspendu)
      case 'invoice.payment_succeeded': {
        const invoice = event.data.object;
        if (invoice.billing_reason === 'subscription_create') break; // déjà géré par checkout.session.completed
        const custDoc = await fsGet('stripe_customers', invoice.customer, token);
        const uid = custDoc?.fields?.uid?.stringValue;
        if (uid) await fsSet('users', uid, { isPro: { booleanValue: true } }, token);
        break;
      }

      // Abonnement résilié : révoquer Pro
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        const custDoc = await fsGet('stripe_customers', sub.customer, token);
        const uid = custDoc?.fields?.uid?.stringValue;
        if (uid) await fsSet('users', uid, { isPro: { booleanValue: false } }, token);
        break;
      }

      // Paiement échoué de manière répétée : révoquer Pro
      case 'customer.subscription.updated': {
        const sub = event.data.object;
        const isActive = ['active', 'trialing'].includes(sub.status);
        if (isActive) break;
        const custDoc = await fsGet('stripe_customers', sub.customer, token);
        const uid = custDoc?.fields?.uid?.stringValue;
        if (uid) await fsSet('users', uid, { isPro: { booleanValue: false } }, token);
        break;
      }

      default:
        break;
    }

    res.status(200).json({ received: true });
  } catch (e) {
    console.error('Webhook error:', e.message);
    res.status(500).json({ error: e.message });
  }
}
