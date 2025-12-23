export { };

const PT_API_PORT = process.env.PT_API_PORT || '3100';
const API_URL = process.env.PT_API_URL || `http://127.0.0.1:${PT_API_PORT}`;

const VAULT = '0x11D79cb50f7ac27A208C5D435440221729837485';
const STRATEGY_ID = '0';

// Default: 1 USDC (6 decimals)
const USDC_AMOUNT = process.env.USDC_AMOUNT || '1000000';

async function main() {
  console.log('🧪 Starting PT API test...');
  console.log(`API_URL: ${API_URL}`);

  // 1) Health check
  try {
    console.log('\n📡 Testing /health...');
    const healthRes = await fetch(`${API_URL}/health`);
    const healthData = await healthRes.json();
    console.log(`Status: ${healthRes.status}`);
    console.log('Response:', JSON.stringify(healthData, null, 2));
  } catch (error) {
    console.error('Health check failed:', error);
    console.error('Is the PT API running? Start it with: npm run dev:pt');
    process.exit(1);
  }

  // 2) getPtAmount
  try {
    console.log('\n🧾 Testing /getPtAmount...');

    const payload = {
      usdc_amount: USDC_AMOUNT,
      vault_address: VAULT,
      strategy_id: STRATEGY_ID,
    };

    console.log('Sending Payload:', JSON.stringify(payload, null, 2));

    const res = await fetch(`${API_URL}/getPtAmount`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const text = await res.text();
    let data: any;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }

    console.log(`Status: ${res.status}`);
    console.log('Response:', typeof data === 'string' ? data : JSON.stringify(data, null, 2));
  } catch (error) {
    console.error('getPtAmount failed:', error);
    process.exit(1);
  }
}

main();


