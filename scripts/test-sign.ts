import { type Order, OrderType } from '../src/types.js';

const API_URL = 'http://localhost:3000';

async function main() {
  console.log('🧪 Starting manual test...');

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

    // Sample data (using dummy addresses)
    const order: any = { // Using any to pass strings for BigInt fields as expected by API
      orderType: OrderType.MINT,
      userWallet: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', // vitalik.eth
      collateralAsset: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC
      collateralAmount: '1000000000', // 1000 USDC (6 decimals)
      yusdAmount: '1000000000000000000', // 1 YUSD (18 decimals)
      slippageAdjustedAmount: '990000000000000000', // 0.99 YUSD
      expiry: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
      nonce: Date.now(),
      additionalData: '0x'
    };

    console.log('Sending Order:', JSON.stringify(order, null, 2));

    const signRes = await fetch(`${API_URL}/sign`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(order)
    });

    if (!signRes.ok) {
      const text = await signRes.text();
      throw new Error(`API Error ${signRes.status}: ${text}`);
    }

    const data = await signRes.json();
    console.log('\n✅ Signature Received!');
    console.log('Signer:', data.signer);
    console.log('Signature:', data.signature);
    console.log('Returned Order:', JSON.stringify(data.order, null, 2));

  } catch (error) {
    console.error('Signing failed:', error);
  }
}

main();

