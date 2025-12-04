const API_URL = 'http://localhost:3000';

async function main() {
  console.log('🧪 Starting manual test (Simple Sign)...');

  // 1. Ping Test
  try {
    console.log('\n📡 Testing /ping...');
    const pingRes = await fetch(`${API_URL}/ping`);
    const pingText = await pingRes.text();
    console.log(`Status: ${pingRes.status}`);
    console.log(`Response: ${pingText}`);
  } catch (error) {
    console.error('Ping failed:', error);
    process.exit(1);
  }

  // 2. Sign Test
  try {
    console.log('\n📝 Testing /sign...');

    const payload = {
      address: "0xdAC17F958D2ee523a2206206994597C13D831ec7", // USDT Address
      amount: "1000000" // 1 USDT
    };

    console.log('Sending Payload:', JSON.stringify(payload, null, 2));

    const signRes = await fetch(`${API_URL}/sign`, {
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
    console.log('\n✅ Signature Received!');
    console.log('Signer:', data.signer);
    console.log('Signed Text:', data.signedText);
    console.log('Signature:', data.signature);

  } catch (error) {
    console.error('Signing failed:', error);
  }
}

main();
