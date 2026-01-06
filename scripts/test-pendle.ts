export { };

const PT_API_PORT = process.env.PT_API_PORT || '3100';
const API_URL = process.env.PT_API_URL || `http://127.0.0.1:${PT_API_PORT}`;

// Pendle market address (default: 0xcc781b043933c10a04409b22aada3a3d1a7f29d4)
const PENDLE_MARKET = process.env.PENDLE_MARKET || '0xcc781b043933c10a04409b22aada3a3d1a7f29d4';
// Default: 10000 ETH (18 decimals) for testing - increased to see more orders selected
const AMOUNT_IN = process.env.AMOUNT_IN || '10000000000000000000000';

async function main() {
  console.log('🧪 Starting Pendle Limit Orders API test...');
  console.log(`API_URL: ${API_URL}`);

  console.log(`Pendle Market: ${PENDLE_MARKET}`);
  console.log(`Amount In: ${AMOUNT_IN}`);

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

  // 2) prepare-limit-orders (buy direction)
  try {
    console.log('\n📊 Testing /api/pendle/prepare-limit-orders (buy)...');

    const payload = {
      market: PENDLE_MARKET,
      amountIn: AMOUNT_IN,
      direction: 'buy' as const,
    };

    console.log('Sending Payload:', JSON.stringify(payload, null, 2));

    const res = await fetch(`${API_URL}/api/pendle/prepare-limit-orders`, {
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
    if (data.success) {
      console.log('✅ Success!');
      console.log(`Encoded Limit Order Data length: ${data.data?.encodedLimitOrderData?.length || 0} chars`);
      console.log(`Encoded Limit Order Data (first 100 chars): ${data.data?.encodedLimitOrderData?.substring(0, 100) || 'N/A'}...`);
      console.log(`Orders count - Normal: ${data.data?.ordersCount?.normalFills || 0}, Flash: ${data.data?.ordersCount?.flashFills || 0}, Total: ${data.data?.ordersCount?.total || 0}`);
      console.log(`Filtered out - Total: ${data.data?.filteredOut?.total || 0}`);
      if (data.data?.filteredOut?.total > 0) {
        console.log('Filtered out details:', JSON.stringify(data.data.filteredOut, null, 2));
      }
    } else {
      console.log('❌ Failed!');
      console.log('Response:', typeof data === 'string' ? data : JSON.stringify(data, null, 2));
    }
  } catch (error) {
    console.error('❌ prepare-limit-orders (buy) failed:', error);
    if (error instanceof Error) {
      console.error('Error message:', error.message);
      console.error('Stack:', error.stack);
    }
    process.exit(1);
  }

  // 3) prepare-limit-orders (sell direction)
  try {
    console.log('\n📊 Testing /api/pendle/prepare-limit-orders (sell)...');

    const payload = {
      market: PENDLE_MARKET,
      amountIn: AMOUNT_IN,
      direction: 'sell' as const,
    };

    console.log('Sending Payload:', JSON.stringify(payload, null, 2));

    const res = await fetch(`${API_URL}/api/pendle/prepare-limit-orders`, {
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
    if (data.success) {
      console.log('✅ Success!');
      console.log(`Encoded Limit Order Data length: ${data.data?.encodedLimitOrderData?.length || 0} chars`);
      console.log(`Encoded Limit Order Data (first 100 chars): ${data.data?.encodedLimitOrderData?.substring(0, 100) || 'N/A'}...`);
      console.log(`Orders count - Normal: ${data.data?.ordersCount?.normalFills || 0}, Flash: ${data.data?.ordersCount?.flashFills || 0}, Total: ${data.data?.ordersCount?.total || 0}`);
      console.log(`Filtered out - Total: ${data.data?.filteredOut?.total || 0}`);
      if (data.data?.filteredOut?.total > 0) {
        console.log('Filtered out details:', JSON.stringify(data.data.filteredOut, null, 2));
      }
    } else {
      console.log('❌ Failed!');
      console.log('Response:', typeof data === 'string' ? data : JSON.stringify(data, null, 2));
    }
  } catch (error) {
    console.error('❌ prepare-limit-orders (sell) failed:', error);
    if (error instanceof Error) {
      console.error('Error message:', error.message);
      console.error('Stack:', error.stack);
    }
    process.exit(1);
  }

  console.log('\n✅ All Pendle tests completed!');
}

main();

