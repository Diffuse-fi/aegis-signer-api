import express, { type NextFunction, type Request, type Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import { decodeFunctionResult, encodeFunctionData, isAddress, parseAbi, type Address, type Hex } from 'viem';
import { ptConfig } from './pt-config.js';

const USDC_ADDRESS = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' as const satisfies Address;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as const satisfies Address;

const MAX_UINT256 = (2n ** 256n) - 1n;

const erc20Abi = parseAbi(['function approve(address spender, uint256 amount) external returns (bool)']);
const viewerAbi = parseAbi([
  'function simulatePtBuy(address from, address vault, uint256 strategyId, uint256 baseAssetAmount, bytes data) external returns (bool finished, uint256[] amounts)',
]);

type EthCallManyTx = {
  from?: Hex;
  to: Hex;
  data: Hex;
  value?: Hex;
};

type EthCallManyBundle = {
  transactions: EthCallManyTx[];
  blockOverride?: Record<string, unknown>;
};

const escapeForSingleQuotes = (value: string): string => value.replace(/'/g, `'\\''`);

const toEthCallManyCurl = (rpcUrl: string, body: unknown): string => {
  const json = JSON.stringify(body);
  return `curl -s -X POST '${rpcUrl}' -H 'content-type: application/json' --data '${escapeForSingleQuotes(json)}'`;
};

const pickString = (value: unknown): string | undefined => {
  if (typeof value === 'string') return value;
  if (Array.isArray(value) && typeof value[0] === 'string') return value[0];
  return undefined;
};

const parseBigIntParam = (raw: string, name: string): bigint => {
  if (!/^\d+$/.test(raw)) {
    throw new Error(`Invalid ${name} (must be a non-negative integer string)`);
  }
  try {
    return BigInt(raw);
  } catch {
    throw new Error(`Invalid ${name} (cannot parse as bigint)`);
  }
};

const extractEthCallManyOutput = (result: unknown): Hex | null => {
  if (typeof result === 'string' && result.startsWith('0x')) return result as Hex;
  if (!result || typeof result !== 'object') return null;

  const r = result as Record<string, unknown>;
  const candidates = [r.output, r.returnData, r.data, r.result, r.value];
  for (const c of candidates) {
    if (typeof c === 'string' && c.startsWith('0x')) return c as Hex;
  }
  return null;
};

async function ethCallMany(bundles: EthCallManyBundle[]) {
  const rpcBody = {
    jsonrpc: '2.0',
    id: 1,
    method: 'eth_callMany',
    params: [bundles],
  };

  if (ptConfig.debug) {
    console.log('[eth_callMany] curl:');
    console.log(toEthCallManyCurl(ptConfig.alchemy.rpcUrl, rpcBody));
  }

  const resp = await fetch(ptConfig.alchemy.rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(rpcBody),
  });

  const text = await resp.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`Alchemy RPC returned non-JSON response (status ${resp.status})`);
  }

  if (!resp.ok) {
    const details = json?.error?.message ? `: ${json.error.message}` : `: ${text}`;
    throw new Error(`Alchemy RPC error (status ${resp.status})${details}`);
  }

  if (json?.error) {
    throw new Error(`Alchemy RPC error: ${json.error?.message || 'Unknown error'}`);
  }

  return json;
}

const app = express();

app.use(helmet());
app.set('trust proxy', 1);

app.use(cors({
  origin: ptConfig.corsOrigin,
  credentials: false,
}));
app.use(morgan('dev'));
app.use(express.json({ limit: '10kb' }));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests from this IP, please try again later.',
  validate: { xForwardedForHeader: false },
}));

app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({
    status: 'ok',
    service: 'pt-api',
    usdcHolder: ptConfig.usdcHolder,
    viewerAddress: ptConfig.viewerAddress,
  });
});

// POST /getPtAmount
// Body: { usdc_amount: "123", vault_address: "0x...", strategy_id: "1" }
// Also supports camelCase keys and query params for convenience.
app.all('/getPtAmount', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    if (req.method !== 'POST' && req.method !== 'GET') {
      res.status(405).json({ error: 'Method not allowed' });
      return;
    }

    const usdcAmountRaw =
      pickString((req.body as any)?.usdc_amount) ??
      pickString((req.body as any)?.usdcAmount) ??
      pickString((req.query as any)?.usdc_amount) ??
      pickString((req.query as any)?.usdcAmount);

    const vaultRaw =
      pickString((req.body as any)?.vault_address) ??
      pickString((req.body as any)?.vaultAddress) ??
      pickString((req.body as any)?.vault) ??
      pickString((req.query as any)?.vault_address) ??
      pickString((req.query as any)?.vaultAddress) ??
      pickString((req.query as any)?.vault);

    const strategyIdRaw =
      pickString((req.body as any)?.strategy_id) ??
      pickString((req.body as any)?.strategyId) ??
      pickString((req.query as any)?.strategy_id) ??
      pickString((req.query as any)?.strategyId);

    if (!usdcAmountRaw) {
      res.status(400).json({ error: 'Missing usdc_amount' });
      return;
    }
    if (!vaultRaw) {
      res.status(400).json({ error: 'Missing vault_address' });
      return;
    }
    if (!strategyIdRaw) {
      res.status(400).json({ error: 'Missing strategy_id' });
      return;
    }

    if (!isAddress(vaultRaw)) {
      res.status(400).json({ error: 'Invalid vault_address' });
      return;
    }

    const usdcAmount = parseBigIntParam(usdcAmountRaw, 'usdc_amount');
    const strategyId = parseBigIntParam(strategyIdRaw, 'strategy_id');
    const vault = vaultRaw as Address;

    const approveData = encodeFunctionData({
      abi: erc20Abi,
      functionName: 'approve',
      args: [ptConfig.viewerAddress, MAX_UINT256],
    });

    const simulateData = encodeFunctionData({
      abi: viewerAbi,
      functionName: 'simulatePtBuy',
      args: [ptConfig.usdcHolder, vault, strategyId, usdcAmount, '0x'],
    });

    const bundles: EthCallManyBundle[] = [
      {
        transactions: [
          // 1) approve from USDC holder to USDC contract (spender=viewer, amount=max)
          { from: ptConfig.usdcHolder, to: USDC_ADDRESS, data: approveData },
          // 2) simulatePtBuy call from ZERO_ADDRESS; first arg "from" is the USDC holder
          { from: ZERO_ADDRESS, to: ptConfig.viewerAddress, data: simulateData },
        ],
      },
    ];

    const rpcJson = await ethCallMany(bundles);
    const bundleResult = rpcJson?.result?.[0];
    const secondResult = Array.isArray(bundleResult) ? bundleResult[1] : undefined;

    if (secondResult && typeof secondResult === 'object' && (secondResult as any).error) {
      const err = (secondResult as any).error;
      const msg = typeof err === 'string' ? err : (err?.message || 'Unknown error');
      res.status(502).json({ error: `eth_callMany simulatePtBuy failed: ${msg}`, raw: secondResult });
      return;
    }

    const output = extractEthCallManyOutput(secondResult);
    if (!output) {
      res.status(502).json({ error: 'Unexpected eth_callMany response shape (missing output)', raw: rpcJson?.result });
      return;
    }

    const decoded = decodeFunctionResult({
      abi: viewerAbi,
      functionName: 'simulatePtBuy',
      data: output,
    }) as unknown as readonly [boolean, readonly bigint[]];

    const finished = decoded[0];
    const amounts = decoded[1].map((x) => x.toString());

    res.status(200).json({ finished, amounts });
  } catch (err) {
    next(err);
  }
});

// Centralized Error Handling
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[PT-API Error]', err.message);
  if (res.headersSent) return;
  res.status(500).json({ error: err.message || 'Internal Server Error' });
});

app.listen(ptConfig.port, '127.0.0.1', () => {
  console.log(`🚀 PT API running on port ${ptConfig.port} (bound to 127.0.0.1)`);
  console.log(`🔗 Alchemy RPC: ${ptConfig.alchemy.rpcUrl.replace(ptConfig.alchemy.apiKey, '***')}`);
  console.log(`👤 USDC holder: ${ptConfig.usdcHolder}`);
  console.log(`🔭 Viewer: ${ptConfig.viewerAddress}`);
});


