export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
  if (!STRIPE_SECRET_KEY) return res.status(500).json({ error: 'Stripe key not configured' });

  try {
    const { email } = req.body;
    const origin = req.headers.origin || 'https://scoreviral.eu';

    const params = new URLSearchParams({
      'mode': 'subscription',
      'line_items[0][price]': 'price_1TFx1T24qOkbqtXoDeWNdq79',
      'line_items[0][quantity]': '1',
      'success_url': `${origin}/?success=true`,
      'cancel_url': `${origin}/?canceled=true`,
      'allow_promotion_codes': 'true',
      'billing_address_collection': 'auto',
      'payment_method_types[0]': 'card',
    });

    if (email) params.append('customer_email', email);

    const response = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    const data = await response.json();
    if (!response.ok) return res.status(500).json({ error: data.error?.message || 'Stripe error' });
    res.status(200).json({ url: data.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}
