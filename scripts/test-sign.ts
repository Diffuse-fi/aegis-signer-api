const API_URL = 'http://localhost:3000';

async function main() {
  console.log('🧪 Starting manual test (Aegis Sign & Mint)...');

  // 1. Health Check Test
  try {
    console.log('\n📡 Testing /health...');
    const healthRes = await fetch(`${API_URL}/health`);
    const healthData = await healthRes.json();
    console.log(`Status: ${healthRes.status}`);
    console.log(`Response:`, JSON.stringify(healthData, null, 2));
  } catch (error) {
    console.error('Health check failed:', error);
    process.exit(1);
  }

  // 2. Sign Test
  try {
    console.log('\n📝 Testing /mint...');

    const payload = {
      collateral_amount: "1000000",
      slippage: 1,
      collateral_asset: "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    };

    console.log('Sending Payload:', JSON.stringify(payload, null, 2));

    const signRes = await fetch(`${API_URL}/mint`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    if (!signRes.ok) {
      const text = await signRes.text();
      throw new Error(`API Error ${signRes.status}: ${text}`);
    }

    const data = await signRes.json();
    console.log('\n✅ Aegis Response Received!');

    if (data.signerSignature) {
      console.log('\n📝 Intermediate Signature (sent to Aegis):');
      console.log(data.signerSignature);
    }

    if (data.encodedData) {
      console.log('\n📦 Encoded Data (for Smart Contract):');
      console.log(data.encodedData);

      if (data.data?.order) {
        console.log('\n📊 Order Details:');
        console.log(`yusd_amount:             ${data.data.order.yusd_amount}`);
        console.log(`slippage_adjusted_amount:${data.data.order.slippage_adjusted_amount}`);

        const expiry = data.data.order.expiry;
        const expiryDate = new Date(Number(expiry) * 1000).toLocaleString('en-GB', { timeZone: 'CET', timeZoneName: 'short' });
        console.log(`expiry:                  ${expiry} (${expiryDate})`);

        console.log(`nonce:                   ${data.data.order.nonce}`);
        console.log(`additional_data:         ${data.data.order.additional_data}`);
      }

      if (data.data?.signature) {
        console.log('\n✍️  Signature (from Aegis):');
        console.log(data.data.signature);
      }
    } else {
      console.log(JSON.stringify(data, null, 2));
    }

  } catch (error) {
    console.error('Signing failed:', error);
  }
}

main();
