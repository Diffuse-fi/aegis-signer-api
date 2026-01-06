export { };

const PT_API_PORT = process.env.PT_API_PORT || '3100';
const API_URL = process.env.PT_API_URL || `http://127.0.0.1:${PT_API_PORT}`;

// CAP-USDC adapter
const ADAPTER = '0x98271E06b882eb0a35Ca4739c2F80acFA7e2Aa91';

// 10000 CAP (18 decimals)
const AMOUNT = '10000000000000000000000';

async function main() {
  console.log('🧪 Starting simulateTokenSale test...');
  console.log(`API_URL: ${API_URL}`);
  console.log(`Adapter: ${ADAPTER}`);
  console.log(`Amount: ${AMOUNT} (10000 CAP with 18 decimals)`);

  try {
    console.log('\n📡 Testing /simulateTokenSale...');

    const payload = {
      adapters: [ADAPTER],
      amount: AMOUNT,
      data: '0x',
    };

    console.log('Sending Payload:', JSON.stringify(payload, null, 2));

    const res = await fetch(`${API_URL}/simulateTokenSale`, {
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

    if (res.status === 200 && data.balanceChanges) {
      console.log('\n✅ Success!');
      console.log('Balance Changes:');
      data.balanceChanges.forEach((change: any, index: number) => {
        console.log(`  Adapter ${index}: token ${change.token}, change: ${change.change}`);
      });
      console.log('\nBuy Results:');
      data.buyResults.forEach((result: any, index: number) => {
        console.log(`  Adapter ${index}: finished=${result.finished}, amountOut=${result.amountOut}`);
      });
    } else if (data.error && data.tokenIn) {
      console.log('\n⚠️  TOKEN_IN not found in token-holders.json');
      console.log(`Please add to token-holders.json: "${data.tokenIn}": "<holder_address>"`);
      console.log('\nTo get holder address, check Etherscan or use a known holder.');
    }
  } catch (error: any) {
    console.error('simulateTokenSale failed:', error.message);
    if (error.message.includes('fetch')) {
      console.error('Is the PT API running? Start it with: npm run dev:pt');
    }
    process.exit(1);
  }
}

main();

