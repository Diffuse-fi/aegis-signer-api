import express, { type NextFunction, type Request, type Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import { decodeFunctionResult, encodeFunctionData, isAddress, parseAbi, decodeErrorResult, encodeAbiParameters, parseAbiParameters, type Address, type Hex } from 'viem';
import { ptConfig } from './pt-config.js';

const USDC_ADDRESS = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' as const satisfies Address;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as const satisfies Address;

const MAX_UINT256 = (2n ** 256n) - 1n;

// Pendle constants
const IMPLIED_RATE_TIME = 365n * 24n * 60n * 60n; // 1 year in seconds
const PRECISION = 10n ** 18n; // 18 decimals precision

const erc20Abi = parseAbi(['function approve(address spender, uint256 amount) external returns (bool)']);
const viewerAbi = parseAbi([
  'function simulatePtBuy(address from, address vault, uint256 strategyId, uint256 baseAssetAmount, bytes data) external returns (bool finished, uint256[] amounts)',
  'function simulatePtBuyBSLow(address from, address vault, uint256 strategyId, uint256 targetPtAmount, uint256 precisionBps, bytes memory data) external returns (bool finished, uint256 baseAssetAmount, uint256[] memory amounts)',
]);
const vaultAbi = parseAbi([
  'function availableLiquidity() external view returns (uint256)',
  'function previewBorrow(address forUser, uint256 strategyId, uint8 collateralType, uint256 collateralAmount, uint256 assetsToBorrow, bytes memory data) external returns (uint256[] memory assetsReceived)',
]);

// Pendle Market ABI
// Using JSON format for complex tuple types that parseAbi doesn't support well
const pendleMarketAbi = [
  {
    name: 'readTokens',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [
      { name: 'SY', type: 'address' },
      { name: 'PT', type: 'address' },
      { name: 'YT', type: 'address' },
    ],
  },
  {
    name: 'swapExactSyForPt',
    type: 'function',
    stateMutability: 'view', // Changed to view for simulation
    inputs: [
      { name: 'receiver', type: 'address' },
      { name: 'exactSyIn', type: 'uint256' },
      {
        name: 'data',
        type: 'tuple',
        components: [
          { name: 'guessMin', type: 'uint256' },
          { name: 'guessMax', type: 'uint256' },
          { name: 'guessOffchain', type: 'uint256' },
          { name: 'maxIteration', type: 'uint256' },
          { name: 'eps', type: 'uint256' },
        ],
      },
    ],
    outputs: [
      { name: 'netSyIn', type: 'uint256' },
      { name: 'netPtOut', type: 'uint256' },
      { name: 'netSyFee', type: 'uint256' },
    ],
  },
  {
    name: 'swapExactPtForSy',
    type: 'function',
    stateMutability: 'view', // Changed to view for simulation
    inputs: [
      { name: 'receiver', type: 'address' },
      { name: 'exactPtIn', type: 'uint256' },
      {
        name: 'data',
        type: 'tuple',
        components: [
          { name: 'guessMin', type: 'uint256' },
          { name: 'guessMax', type: 'uint256' },
          { name: 'guessOffchain', type: 'uint256' },
          { name: 'maxIteration', type: 'uint256' },
          { name: 'eps', type: 'uint256' },
        ],
      },
    ],
    outputs: [
      { name: 'netPtIn', type: 'uint256' },
      { name: 'netSyOut', type: 'uint256' },
      { name: 'netSyFee', type: 'uint256' },
    ],
  },
] as const;

// Pendle SY (Standardized Yield) ABI
const pendleSyAbi = parseAbi([
  'function getTokensIn() external view returns (address[] memory)',
  'function getTokensOut() external view returns (address[] memory)',
  'function exchangeRate() external view returns (uint256)', // PYIndex from SY
]);

// Pendle YT (Yield Token) ABI
const pendleYtAbi = parseAbi([
  'function expiry() external view returns (uint256)',
]);

// Pendle Router ABI (for getting Limit Router address)
const pendleRouterAbi = parseAbi([
  'function limitRouter() external view returns (address)',
  'function getLimitRouter() external view returns (address)',
]);

// Pendle Router V4 address for Ethereum mainnet
const PENDLE_ROUTER_V4_ADDRESS = '0x888888888889758F76e7103c6CbF23ABbF58F946' as Address;

// Pendle Limit Router ABI
// Using JSON format for complex tuple types that parseAbi doesn't support well
const pendleLimitRouterAbi = [
  {
    name: 'nonce',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'maker', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: '_checkSig',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      {
        name: 'order',
        type: 'tuple',
        components: [
          { name: 'salt', type: 'uint256' },
          { name: 'expiry', type: 'uint256' },
          { name: 'nonce', type: 'uint256' },
          { name: 'orderType', type: 'uint8' },
          { name: 'token', type: 'address' },
          { name: 'YT', type: 'address' },
          { name: 'maker', type: 'address' },
          { name: 'receiver', type: 'address' },
          { name: 'makingAmount', type: 'uint256' },
          { name: 'lnImpliedRate', type: 'uint256' },
          { name: 'failSafeRate', type: 'uint256' },
          { name: 'permit', type: 'bytes' },
        ],
      },
      { name: 'signature', type: 'bytes' },
    ],
    outputs: [
      { name: 'orderHash', type: 'bytes32' },
      { name: 'remainingAmount', type: 'uint256' },
      { name: 'filledAmount', type: 'uint256' },
    ],
  },
] as const;

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

// Pendle Limit Orders Types
interface Order {
  salt: string | bigint;
  expiry: string | bigint;
  nonce: string | bigint;
  orderType: number; // 0 = SY_FOR_PT, 1 = PT_FOR_SY, 2 = SY_FOR_YT, 3 = YT_FOR_SY
  token: string;
  YT: string;
  maker: string;
  receiver: string;
  makingAmount: string | bigint;
  lnImpliedRate: string | bigint;
  failSafeRate: string | bigint;
  permit?: string;
}

interface FillOrderParams {
  order: Order;
  signature: string;
  makingAmount: string | bigint;
}

interface PendleApiOrder {
  id: string;
  signature: string;
  chainId: number;
  salt: string;
  expiry: string;
  nonce: string;
  type: number;
  token: string;
  yt: string;
  maker: string;
  receiver: string;
  makingAmount: string;
  currentMakingAmount: string;
  lnImpliedRate: string;
  failSafeRate: string;
  permit: string;
  pt?: string;
  sy?: string;
}

interface PendleApiResult {
  order: PendleApiOrder;
  makingAmount: string;
  netFromTaker?: string;
  netToTaker?: string;
}

interface PendleApiResponse {
  total: number;
  limit: number;
  skip: number;
  results: PendleApiResult[];
}

interface LimitOrderData {
  limitRouter: string;
  epsSkipMarket: string | bigint;
  normalFills: FillOrderParams[];
  flashFills: FillOrderParams[];
  optData?: string;
}

interface FilterStats {
  invalidSignature: number;
  expired: number;
  wrongNonce: number;
  zeroRemaining: number;
  wrongType: number;
  worseThanMarket: number;
}

interface PrepareLimitOrdersRequest {
  market: string;
  amountIn: string;
  direction: 'buy' | 'sell';
}

// Known Pendle Limit Router addresses by chainId
// Note: The address should typically come from the Pendle API response.
// This is a fallback for Ethereum mainnet only.
// Pendle Limit Router address for Ethereum mainnet
// Can be overridden via PENDLE_LIMIT_ROUTER_ADDRESS environment variable
const getPendleLimitRouterAddress = (chainId: number): Address | null => {
  const envAddress = process.env.PENDLE_LIMIT_ROUTER_ADDRESS;
  if (envAddress && isAddress(envAddress)) {
    return envAddress as Address;
  }

  // Known addresses by chainId
  const addresses: Record<number, Address> = {
    // Ethereum mainnet - Pendle Limit Router address
    1: '0x000000000000c9B3E2C3Ec88B1B4c0cD853f4321' as Address,
  };

  return addresses[chainId] || null;
};

const PENDLE_LIMIT_ROUTER_ADDRESSES: Record<number, Address> = {
  1: getPendleLimitRouterAddress(1) || ('0x000000000000c9B3E2C3Ec88B1B4c0cD853f4321' as Address),
};

// Helper function to normalize bigint values
const normalizeBigInt = (value: string | bigint | number): bigint => {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'string') {
    if (value.startsWith('0x')) return BigInt(value);
    return BigInt(value);
  }
  return BigInt(value);
};

// Helper function to normalize address
const normalizeAddress = (addr: string): Address => {
  return addr.toLowerCase() as Address;
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
  max: 5000,
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
      console.error('[Contract Error] eth_callMany simulatePtBuy failed:', {
        error: err,
        message: msg,
        raw: secondResult,
        vault,
        strategyId,
        usdcAmount: usdcAmount.toString()
      });
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

// POST /getPtBuyBSLow
// Body: { target_pt_amount: "123", vault_address: "0x...", strategy_id: "1", precision_bps: "50" (optional) }
// Also supports camelCase keys and query params for convenience.
app.all('/getPtBuyBSLow', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    if (req.method !== 'POST' && req.method !== 'GET') {
      res.status(405).json({ error: 'Method not allowed' });
      return;
    }

    const targetPtAmountRaw =
      pickString((req.body as any)?.target_pt_amount) ??
      pickString((req.body as any)?.targetPtAmount) ??
      pickString((req.query as any)?.target_pt_amount) ??
      pickString((req.query as any)?.targetPtAmount);

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

    const precisionBpsRaw =
      pickString((req.body as any)?.precision_bps) ??
      pickString((req.body as any)?.precisionBps) ??
      pickString((req.query as any)?.precision_bps) ??
      pickString((req.query as any)?.precisionBps) ??
      '50'; // Default to 50 (0.5%)

    const dataRaw =
      pickString((req.body as any)?.data) ??
      pickString((req.query as any)?.data) ??
      '0x';

    if (!targetPtAmountRaw) {
      res.status(400).json({ error: 'Missing target_pt_amount' });
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

    const targetPtAmount = parseBigIntParam(targetPtAmountRaw, 'target_pt_amount');
    const strategyId = parseBigIntParam(strategyIdRaw, 'strategy_id');
    const precisionBps = parseBigIntParam(precisionBpsRaw, 'precision_bps');
    const vault = vaultRaw as Address;

    let data: Hex = '0x' as Hex;
    if (dataRaw && dataRaw.startsWith('0x')) {
      data = dataRaw as Hex;
    } else if (dataRaw && dataRaw !== '0x') {
      res.status(400).json({ error: 'Invalid data (must be hex string starting with 0x)' });
      return;
    }

    const approveData = encodeFunctionData({
      abi: erc20Abi,
      functionName: 'approve',
      args: [ptConfig.viewerAddress, MAX_UINT256],
    });

    const simulateData = encodeFunctionData({
      abi: viewerAbi,
      functionName: 'simulatePtBuyBSLow',
      args: [ptConfig.usdcHolder, vault, strategyId, targetPtAmount, precisionBps, data],
    });

    const bundles: EthCallManyBundle[] = [
      {
        transactions: [
          // 1) approve from USDC holder to USDC contract (spender=viewer, amount=max)
          { from: ptConfig.usdcHolder, to: USDC_ADDRESS, data: approveData },
          // 2) simulatePtBuyBSLow call from ZERO_ADDRESS; first arg "from" is the USDC holder
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
      console.error('[Contract Error] eth_callMany simulatePtBuyBSLow failed:', {
        error: err,
        message: msg,
        raw: secondResult,
        vault,
        strategyId,
        targetPtAmount: targetPtAmount.toString(),
        precisionBps: precisionBps.toString()
      });
      res.status(502).json({ error: `eth_callMany simulatePtBuyBSLow failed: ${msg}`, raw: secondResult });
      return;
    }

    const output = extractEthCallManyOutput(secondResult);
    if (!output) {
      res.status(502).json({ error: 'Unexpected eth_callMany response shape (missing output)', raw: rpcJson?.result });
      return;
    }

    const decoded = decodeFunctionResult({
      abi: viewerAbi,
      functionName: 'simulatePtBuyBSLow',
      data: output,
    }) as unknown as readonly [boolean, bigint, readonly bigint[]];

    const finished = decoded[0];
    const baseAssetAmount = decoded[1].toString();
    const amounts = decoded[2].map((x) => x.toString());

    res.status(200).json({ finished, baseAssetAmount, amounts });
  } catch (err) {
    next(err);
  }
});

// POST /previewBorrow
// Body: { vault_address: "0x...", strategy_id: "1", collateral_type: "0", collateral_amount: "123", assets_to_borrow: "456", data: "0x..." }
// Also supports camelCase keys and query params for convenience.
app.all('/previewBorrow', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    if (req.method !== 'POST' && req.method !== 'GET') {
      res.status(405).json({ error: 'Method not allowed' });
      return;
    }

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

    const collateralTypeRaw =
      pickString((req.body as any)?.collateral_type) ??
      pickString((req.body as any)?.collateralType) ??
      pickString((req.query as any)?.collateral_type) ??
      pickString((req.query as any)?.collateralType);

    const collateralAmountRaw =
      pickString((req.body as any)?.collateral_amount) ??
      pickString((req.body as any)?.collateralAmount) ??
      pickString((req.query as any)?.collateral_amount) ??
      pickString((req.query as any)?.collateralAmount);

    const assetsToBorrowRaw =
      pickString((req.body as any)?.assets_to_borrow) ??
      pickString((req.body as any)?.assetsToBorrow) ??
      pickString((req.query as any)?.assets_to_borrow) ??
      pickString((req.query as any)?.assetsToBorrow);

    const dataRaw =
      pickString((req.body as any)?.data) ??
      pickString((req.query as any)?.data) ??
      '0x';

    if (!vaultRaw) {
      res.status(400).json({ error: 'Missing vault_address' });
      return;
    }
    if (!strategyIdRaw) {
      res.status(400).json({ error: 'Missing strategy_id' });
      return;
    }
    if (collateralTypeRaw === undefined || collateralTypeRaw === null) {
      res.status(400).json({ error: 'Missing collateral_type' });
      return;
    }
    if (!collateralAmountRaw) {
      res.status(400).json({ error: 'Missing collateral_amount' });
      return;
    }
    if (!assetsToBorrowRaw) {
      res.status(400).json({ error: 'Missing assets_to_borrow' });
      return;
    }

    if (!isAddress(vaultRaw)) {
      res.status(400).json({ error: 'Invalid vault_address' });
      return;
    }

    const vault = vaultRaw as Address;
    const strategyId = parseBigIntParam(strategyIdRaw, 'strategy_id');
    const collateralType = parseBigIntParam(collateralTypeRaw, 'collateral_type');
    if (collateralType !== 0n && collateralType !== 1n) {
      res.status(400).json({ error: 'Invalid collateral_type (must be 0 or 1)' });
      return;
    }
    const collateralAmount = parseBigIntParam(collateralAmountRaw, 'collateral_amount');
    const assetsToBorrow = parseBigIntParam(assetsToBorrowRaw, 'assets_to_borrow');

    let data: Hex = '0x' as Hex;
    if (dataRaw && dataRaw.startsWith('0x')) {
      data = dataRaw as Hex;
    } else if (dataRaw) {
      res.status(400).json({ error: 'Invalid data (must be hex string starting with 0x)' });
      return;
    }

    const approveData = encodeFunctionData({
      abi: erc20Abi,
      functionName: 'approve',
      args: [vault, MAX_UINT256],
    });

    const availableLiquidityData = encodeFunctionData({
      abi: vaultAbi,
      functionName: 'availableLiquidity',
      args: [],
    });

    // Convert collateralType to uint8 (0-255)
    const collateralTypeNum = Number(collateralType);
    if (collateralTypeNum < 0 || collateralTypeNum > 255) {
      res.status(400).json({ error: 'Invalid collateral_type (must be 0-255 for uint8)' });
      return;
    }

    if (ptConfig.debug) {
      console.log('[previewBorrow] Parameters:', {
        forUser: ptConfig.usdcHolder,
        strategyId: strategyId.toString(),
        collateralType: collateralTypeNum,
        collateralAmount: collateralAmount.toString(),
        assetsToBorrow: assetsToBorrow.toString(),
        data: data,
        vault,
      });
    }

    const previewBorrowData = encodeFunctionData({
      abi: vaultAbi,
      functionName: 'previewBorrow',
      args: [ptConfig.usdcHolder, strategyId, collateralTypeNum, collateralAmount, assetsToBorrow, data],
    });

    if (ptConfig.debug) {
      console.log('[previewBorrow] Encoded data:', previewBorrowData);
      console.log('[previewBorrow] Call will be made from:', ZERO_ADDRESS);
      // Generate cast call commands for manual testing
      console.log('[previewBorrow] Cast call commands:');
      console.log('1) approve:');
      console.log(`cast call ${USDC_ADDRESS} "approve(address,uint256)" ${vault} ${MAX_UINT256.toString()} --from ${ptConfig.usdcHolder}`);
      console.log('2) availableLiquidity:');
      console.log(`cast call ${vault} "availableLiquidity()" --from 0x0000000000000000000000000000000000000000`);
      console.log('3) previewBorrow:');
      console.log(`cast call ${vault} "previewBorrow(address,uint256,uint8,uint256,uint256,bytes)" ${ptConfig.usdcHolder} ${strategyId.toString()} ${collateralTypeNum} ${collateralAmount.toString()} ${assetsToBorrow.toString()} ${data} --from 0x0000000000000000000000000000000000000000`);
    }

    const bundles: EthCallManyBundle[] = [
      {
        transactions: [
          // 1) approve from USDC holder to USDC contract (spender=vault, amount=max)
          { from: ptConfig.usdcHolder, to: USDC_ADDRESS, data: approveData },
          // 2) availableLiquidity call from ZERO_ADDRESS to vault
          { from: ZERO_ADDRESS, to: vault, data: availableLiquidityData },
          // 3) previewBorrow call from ZERO_ADDRESS to vault
          { from: ZERO_ADDRESS, to: vault, data: previewBorrowData },
        ],
      },
    ];

    const rpcJson = await ethCallMany(bundles);
    const bundleResult = rpcJson?.result?.[0];
    const results = Array.isArray(bundleResult) ? bundleResult : [];

    // Check approve result (index 0)
    const approveResult = results[0];
    if (approveResult && typeof approveResult === 'object' && (approveResult as any).error) {
      const err = (approveResult as any).error;
      const msg = typeof err === 'string' ? err : (err?.message || 'Unknown error');
      console.error('[Contract Error] eth_callMany approve failed:', {
        error: err,
        message: msg,
        raw: approveResult,
        vault,
        strategyId
      });
      res.status(502).json({ error: `eth_callMany approve failed: ${msg}`, raw: approveResult });
      return;
    }

    // Check availableLiquidity result (index 1)
    const liquidityResult = results[1];
    if (liquidityResult && typeof liquidityResult === 'object' && (liquidityResult as any).error) {
      const err = (liquidityResult as any).error;
      const msg = typeof err === 'string' ? err : (err?.message || 'Unknown error');
      console.error('[Contract Error] eth_callMany availableLiquidity failed:', {
        error: err,
        message: msg,
        raw: liquidityResult,
        vault
      });
      res.status(502).json({ error: `eth_callMany availableLiquidity failed: ${msg}`, raw: liquidityResult });
      return;
    }

    const liquidityOutput = extractEthCallManyOutput(liquidityResult);
    if (!liquidityOutput) {
      res.status(502).json({ error: 'Unexpected eth_callMany response shape (missing availableLiquidity output)', raw: rpcJson?.result });
      return;
    }

    const availableLiquidity = decodeFunctionResult({
      abi: vaultAbi,
      functionName: 'availableLiquidity',
      data: liquidityOutput,
    }) as unknown as bigint;

    if (availableLiquidity < assetsToBorrow) {
      res.status(400).json({
        error: 'Insufficient liquidity in vault',
        availableLiquidity: availableLiquidity.toString(),
        requestedBorrow: assetsToBorrow.toString(),
      });
      return;
    }

    // Check previewBorrow result (index 2)
    const previewBorrowResult = results[2];
    if (previewBorrowResult && typeof previewBorrowResult === 'object' && (previewBorrowResult as any).error) {
      const err = (previewBorrowResult as any).error;
      const msg = typeof err === 'string' ? err : (err?.message || 'Unknown error');

      // Try to decode error data if available
      let decodedError: any = null;
      const errorData = (previewBorrowResult as any).data || (err as any)?.data;
      if (errorData && typeof errorData === 'string' && errorData.startsWith('0x')) {
        try {
          decodedError = decodeErrorResult({ data: errorData as Hex });
        } catch {
          // Ignore decode errors
        }
      }

      const errorDetails = {
        error: err,
        message: msg,
        raw: previewBorrowResult,
        vault,
        strategyId,
        collateralType: collateralType.toString(),
        collateralAmount: collateralAmount.toString(),
        assetsToBorrow: assetsToBorrow.toString(),
        forUser: ptConfig.usdcHolder,
        callFrom: ZERO_ADDRESS,
        data: data,
        ...(decodedError ? { decodedError: decodedError.errorName || decodedError } : {}),
      };

      console.error('[Contract Error] eth_callMany previewBorrow failed:', errorDetails);
      res.status(502).json({
        error: `eth_callMany previewBorrow failed: ${msg}`,
        raw: previewBorrowResult,
        ...(decodedError ? { decodedError: decodedError.errorName || decodedError } : {}),
      });
      return;
    }

    const output = extractEthCallManyOutput(previewBorrowResult);
    if (!output) {
      res.status(502).json({ error: 'Unexpected eth_callMany response shape (missing previewBorrow output)', raw: rpcJson?.result });
      return;
    }

    const decoded = decodeFunctionResult({
      abi: vaultAbi,
      functionName: 'previewBorrow',
      data: output,
    }) as unknown as readonly bigint[];

    const assetsReceived = decoded.map((x) => x.toString());

    res.status(200).json({ assetsReceived });
  } catch (err) {
    next(err);
  }
});

// ==================== Pendle Limit Orders Functions ====================

// Get Limit Router address from Pendle Router contract
async function getLimitRouterAddress(chainId: number = 1): Promise<Address | null> {
  try {
    // Try to get from Pendle Router V4
    const limitRouterData = encodeFunctionData({
      abi: pendleRouterAbi,
      functionName: 'limitRouter',
      args: [],
    });

    const bundles: EthCallManyBundle[] = [
      {
        transactions: [
          { from: ZERO_ADDRESS, to: PENDLE_ROUTER_V4_ADDRESS, data: limitRouterData },
        ],
      },
    ];

    const rpcJson = await ethCallMany(bundles);
    const bundleResult = rpcJson?.result?.[0];
    const result = Array.isArray(bundleResult) ? bundleResult[0] : bundleResult;

    if (result && typeof result === 'object' && (result as any).error) {
      // Try alternative function name
      const getLimitRouterData = encodeFunctionData({
        abi: pendleRouterAbi,
        functionName: 'getLimitRouter',
        args: [],
      });

      const bundles2: EthCallManyBundle[] = [
        {
          transactions: [
            { from: ZERO_ADDRESS, to: PENDLE_ROUTER_V4_ADDRESS, data: getLimitRouterData },
          ],
        },
      ];

      const rpcJson2 = await ethCallMany(bundles2);
      const bundleResult2 = rpcJson2?.result?.[0];
      const result2 = Array.isArray(bundleResult2) ? bundleResult2[0] : bundleResult2;

      if (result2 && typeof result2 === 'object' && (result2 as any).error) {
        if (ptConfig.debug) {
          console.log('[Pendle] Failed to get limitRouter from contract, trying alternative methods');
        }
        return null;
      }

      const output2 = extractEthCallManyOutput(result2);
      if (output2) {
        const decoded = decodeFunctionResult({
          abi: pendleRouterAbi,
          functionName: 'getLimitRouter',
          data: output2,
        }) as unknown as Address;
        return decoded;
      }
      return null;
    }

    const output = extractEthCallManyOutput(result);
    if (!output) {
      return null;
    }

    const decoded = decodeFunctionResult({
      abi: pendleRouterAbi,
      functionName: 'limitRouter',
      data: output,
    }) as unknown as Address;

    return decoded;
  } catch (error) {
    if (ptConfig.debug) {
      console.error('[Pendle] Error getting limitRouter from contract:', error);
    }
    return null;
  }
}

// Get tokens from Pendle market
async function getTokensFromMarket(marketAddress: Address): Promise<{
  tokenIn: Address;
  tokenOut: Address;
  SY: Address;
  PT: Address;
  YT: Address;
}> {
  const readTokensData = encodeFunctionData({
    abi: pendleMarketAbi,
    functionName: 'readTokens',
    args: [],
  });

  const bundles: EthCallManyBundle[] = [
    {
      transactions: [
        { from: ZERO_ADDRESS, to: marketAddress, data: readTokensData },
      ],
    },
  ];

  const rpcJson = await ethCallMany(bundles);
  const bundleResult = rpcJson?.result?.[0];
  const result = Array.isArray(bundleResult) ? bundleResult[0] : bundleResult;

  if (result && typeof result === 'object' && (result as any).error) {
    throw new Error(`Failed to read tokens from market: ${(result as any).error?.message || 'Unknown error'}`);
  }

  const output = extractEthCallManyOutput(result);
  if (!output) {
    throw new Error('Failed to get tokens from market: missing output');
  }

  const decoded = decodeFunctionResult({
    abi: pendleMarketAbi,
    functionName: 'readTokens',
    data: output,
  }) as unknown as readonly [Address, Address, Address];

  const [SY, PT, YT] = decoded;
  return { SY, PT, YT, tokenIn: ZERO_ADDRESS, tokenOut: ZERO_ADDRESS }; // Will be set based on direction
}

// Get tokens from SY contract
async function getSyTokens(syAddress: Address, direction: 'buy' | 'sell'): Promise<Address> {
  const functionName = direction === 'buy' ? 'getTokensIn' : 'getTokensOut';
  const getTokensData = encodeFunctionData({
    abi: pendleSyAbi,
    functionName: functionName as 'getTokensIn' | 'getTokensOut',
    args: [],
  });

  const bundles: EthCallManyBundle[] = [
    {
      transactions: [
        { from: ZERO_ADDRESS, to: syAddress, data: getTokensData },
      ],
    },
  ];

  const rpcJson = await ethCallMany(bundles);
  const bundleResult = rpcJson?.result?.[0];
  const result = Array.isArray(bundleResult) ? bundleResult[0] : bundleResult;

  if (result && typeof result === 'object' && (result as any).error) {
    throw new Error(`Failed to get tokens from SY: ${(result as any).error?.message || 'Unknown error'}`);
  }

  const output = extractEthCallManyOutput(result);
  if (!output) {
    throw new Error('Failed to get tokens from SY: missing output');
  }

  const decoded = decodeFunctionResult({
    abi: pendleSyAbi,
    functionName: functionName as 'getTokensIn' | 'getTokensOut',
    data: output,
  }) as unknown as readonly Address[];

  if (decoded.length === 0) {
    throw new Error(`No tokens found in SY ${functionName}`);
  }

  return decoded[0]; // Return first token
}

// Get YT expiry and PYIndex from SY
async function getYtInfo(ytAddress: Address, syAddress: Address): Promise<{ expiry: bigint; pyIndex: bigint }> {
  const expiryData = encodeFunctionData({
    abi: pendleYtAbi,
    functionName: 'expiry',
    args: [],
  });

  const exchangeRateData = encodeFunctionData({
    abi: pendleSyAbi,
    functionName: 'exchangeRate',
    args: [],
  });

  const bundles: EthCallManyBundle[] = [
    {
      transactions: [
        { from: ZERO_ADDRESS, to: ytAddress, data: expiryData },
        { from: ZERO_ADDRESS, to: syAddress, data: exchangeRateData },
      ],
    },
  ];

  const rpcJson = await ethCallMany(bundles);
  const bundleResult = rpcJson?.result?.[0];
  const results = Array.isArray(bundleResult) ? bundleResult : [];

  if (results.length < 2) {
    if (ptConfig.debug) {
      console.error('[YT Info] Unexpected results structure:', {
        bundleResult,
        resultsLength: results.length,
        results,
      });
    }
    throw new Error(`Failed to get YT info: missing results (got ${results.length}, expected 2)`);
  }

  // Check for errors in results
  const expiryResult = results[0];
  const exchangeRateResult = results[1];

  if (expiryResult && typeof expiryResult === 'object' && (expiryResult as any).error) {
    throw new Error(`Failed to get YT expiry: ${(expiryResult as any).error?.message || 'Unknown error'}`);
  }
  if (exchangeRateResult && typeof exchangeRateResult === 'object' && (exchangeRateResult as any).error) {
    // If exchangeRate fails, try to continue with default value or skip price filtering
    if (ptConfig.debug) {
      console.warn('[YT Info] Failed to get SY exchangeRate, will skip price filtering:', (exchangeRateResult as any).error?.message);
    }
    // Return default pyIndex (1e18) if exchangeRate fails
    const expiryOutput = extractEthCallManyOutput(expiryResult);
    if (!expiryOutput) {
      throw new Error('Failed to get YT expiry: missing output');
    }
    const expiry = decodeFunctionResult({
      abi: pendleYtAbi,
      functionName: 'expiry',
      data: expiryOutput,
    }) as bigint;
    return { expiry, pyIndex: PRECISION }; // Default to 1.0
  }

  const expiryOutput = extractEthCallManyOutput(expiryResult);
  const exchangeRateOutput = extractEthCallManyOutput(exchangeRateResult);

  if (!expiryOutput || !exchangeRateOutput) {
    if (ptConfig.debug) {
      console.error('[YT Info] Missing output:', {
        expiryOutput: expiryOutput ? 'present' : 'missing',
        exchangeRateOutput: exchangeRateOutput ? 'present' : 'missing',
        results: results.map((r, i) => ({ index: i, type: typeof r, value: r })),
      });
    }
    throw new Error('Failed to get YT info: missing output');
  }

  const expiry = decodeFunctionResult({
    abi: pendleYtAbi,
    functionName: 'expiry',
    data: expiryOutput,
  }) as bigint;

  const pyIndex = decodeFunctionResult({
    abi: pendleSyAbi,
    functionName: 'exchangeRate',
    data: exchangeRateOutput,
  }) as bigint;

  return { expiry, pyIndex };
}

// Calculate market swap output for exact input amount
// Returns: output amount (PT for buy, SY for sell) for the given input amount
async function calculateMarketSwapOutput(
  marketAddress: Address,
  amountIn: bigint,
  direction: 'buy' | 'sell',
  SY: Address,
  PT: Address
): Promise<bigint> {
  // For buy: calculate how much PT we get for amountIn SY
  // For sell: calculate how much SY we get for amountIn PT

  if (amountIn === 0n) {
    return 0n;
  }

  try {
    if (direction === 'buy') {
      // Calculate PT output for exact SY input: swapExactSyForPt
      const swapData = encodeFunctionData({
        abi: pendleMarketAbi,
        functionName: 'swapExactSyForPt',
        args: [
          ZERO_ADDRESS, // receiver
          amountIn, // exactSyIn - use actual amount, not test amount
          {
            guessMin: 0n,
            guessMax: MAX_UINT256,
            guessOffchain: 0n,
            maxIteration: 256n,
            eps: 1n, // 1 wei precision
          },
        ],
      });

      const bundles: EthCallManyBundle[] = [
        {
          transactions: [{ from: ZERO_ADDRESS, to: marketAddress, data: swapData }],
        },
      ];

      const rpcJson = await ethCallMany(bundles);
      const bundleResult = rpcJson?.result?.[0];
      const result = Array.isArray(bundleResult) ? bundleResult[0] : bundleResult;

      if (result && typeof result === 'object' && (result as any).error) {
        const errorObj = (result as any).error;
        const errorMsg = errorObj?.message || errorObj?.data || JSON.stringify(errorObj) || 'Unknown error';
        if (ptConfig.debug) {
          console.log(`[Market Swap Calculation Error] Full error (buy):`, JSON.stringify(errorObj, null, 2));
          console.log(`[Market Swap Calculation Error] AmountIn: ${amountIn.toString()}`);
        }
        // If swap fails (e.g., insufficient liquidity), return 0 instead of throwing
        // This allows the comparison to continue - if AMM fails, we can't compare, so skip this order
        return 0n;
      }

      const output = extractEthCallManyOutput(result);
      if (!output) {
        if (ptConfig.debug) {
          console.log(`[Market Swap Calculation Error] Missing output (buy). Result:`, JSON.stringify(result, null, 2));
        }
        // If output is missing, return 0 to skip comparison
        return 0n;
      }

      const decoded = decodeFunctionResult({
        abi: pendleMarketAbi,
        functionName: 'swapExactSyForPt',
        data: output,
      }) as readonly [bigint, bigint, bigint]; // [netSyIn, netPtOut, netSyFee]

      const [, netPtOut] = decoded;
      return netPtOut; // Return actual PT output
    } else {
      // Calculate SY output for exact PT input: swapExactPtForSy
      const swapData = encodeFunctionData({
        abi: pendleMarketAbi,
        functionName: 'swapExactPtForSy',
        args: [
          ZERO_ADDRESS, // receiver
          amountIn, // exactPtIn - use actual amount, not test amount
          {
            guessMin: 0n,
            guessMax: MAX_UINT256,
            guessOffchain: 0n,
            maxIteration: 256n,
            eps: 1n, // 1 wei precision
          },
        ],
      });

      const bundles: EthCallManyBundle[] = [
        {
          transactions: [{ from: ZERO_ADDRESS, to: marketAddress, data: swapData }],
        },
      ];

      const rpcJson = await ethCallMany(bundles);
      const bundleResult = rpcJson?.result?.[0];
      const result = Array.isArray(bundleResult) ? bundleResult[0] : bundleResult;

      if (result && typeof result === 'object' && (result as any).error) {
        const errorObj = (result as any).error;
        const errorMsg = errorObj?.message || errorObj?.data || JSON.stringify(errorObj) || 'Unknown error';
        if (ptConfig.debug) {
          console.log(`[Market Swap Calculation Error] Full error (sell):`, JSON.stringify(errorObj, null, 2));
          console.log(`[Market Swap Calculation Error] AmountIn: ${amountIn.toString()}`);
        }
        // If swap fails (e.g., insufficient liquidity), return 0 instead of throwing
        // This allows the comparison to continue - if AMM fails, we can't compare, so skip this order
        return 0n;
      }

      const output = extractEthCallManyOutput(result);
      if (!output) {
        if (ptConfig.debug) {
          console.log(`[Market Swap Calculation Error] Missing output (sell). Result:`, JSON.stringify(result, null, 2));
        }
        // If output is missing, return 0 to skip comparison
        return 0n;
      }

      const decoded = decodeFunctionResult({
        abi: pendleMarketAbi,
        functionName: 'swapExactPtForSy',
        data: output,
      }) as readonly [bigint, bigint, bigint]; // [netPtIn, netSyOut, netSyFee]

      const [, netSyOut] = decoded;
      return netSyOut; // Return actual SY output
    }
  } catch (error) {
    // If market swap calculation fails, return 0 to skip comparison for this amount
    if (ptConfig.debug) {
      console.error('[Market Swap Calculation Error]', error);
    }
    return 0n;
  }
}

// Calculate market swap price (for backward compatibility)
// Returns: price in terms of output/input (e.g., PT per SY for buy, SY per PT for sell)
async function calculateMarketSwapPrice(
  marketAddress: Address,
  amountIn: bigint,
  direction: 'buy' | 'sell',
  SY: Address,
  PT: Address
): Promise<bigint> {
  const output = await calculateMarketSwapOutput(marketAddress, amountIn, direction, SY, PT);
  if (output === 0n || amountIn === 0n) {
    return 0n;
  }
  // Price = output / input
  return (output * PRECISION) / amountIn; // Scale to PRECISION for comparison
}

// Calculate limit order price from lnImpliedRate
// Returns: price in same units as market price (PT per SY for buy, SY per PT for sell)
function calculateLimitOrderPrice(
  order: Order,
  pyIndex: bigint,
  currentTimestamp: bigint,
  direction: 'buy' | 'sell'
): bigint {
  const lnImpliedRate = normalizeBigInt(order.lnImpliedRate);
  const expiry = normalizeBigInt(order.expiry);

  // Calculate time to expiry
  const timeToExpiry = expiry > currentTimestamp ? expiry - currentTimestamp : 0n;

  if (timeToExpiry === 0n) {
    if (ptConfig.debug) {
      console.log(`[Limit Order Price] Expired order: expiry=${expiry.toString()}, current=${currentTimestamp.toString()}`);
    }
    return 0n; // Expired order
  }

  // Calculate exchange rate: e^(lnImpliedRate * timeToExpiry / IMPLIED_RATE_TIME)
  // Using approximation: e^x ≈ 1 + x + x²/2 + x³/6 for small x
  // For precision, we'll use: (1 + lnImpliedRate * timeToExpiry / IMPLIED_RATE_TIME) with scaling

  // Simplified calculation: exchangeRate = 1 + (lnImpliedRate * timeToExpiry) / (IMPLIED_RATE_TIME * PRECISION)
  // lnImpliedRate is already scaled, so we need to account for that
  // Pendle uses: exchangeRate = exp(lnImpliedRate * timeToExpiry / IMPLIED_RATE_TIME)

  // For better precision, use: exchangeRate ≈ PRECISION + (lnImpliedRate * timeToExpiry * PRECISION) / IMPLIED_RATE_TIME
  // But lnImpliedRate might already be in a different scale, so we'll use a simpler approach

  // Calculate: exchangeRate = PRECISION * (1 + lnImpliedRate * timeToExpiry / (IMPLIED_RATE_TIME * PRECISION))
  // Simplified: exchangeRate = PRECISION + (lnImpliedRate * timeToExpiry) / IMPLIED_RATE_TIME
  const exchangeRate = PRECISION + (lnImpliedRate * timeToExpiry) / IMPLIED_RATE_TIME;

  if (exchangeRate === 0n || pyIndex === 0n) {
    if (ptConfig.debug) {
      console.log(`[Limit Order Price] Invalid exchangeRate or pyIndex: exchangeRate=${exchangeRate.toString()}, pyIndex=${pyIndex.toString()}`);
    }
    return 0n;
  }

  // For SY_FOR_YT (orderType 2, buy direction): price = exchangeRate * PYIndex / PRECISION (PT per SY)
  // For YT_FOR_SY (orderType 3, sell direction): price = PRECISION / (exchangeRate * PYIndex / PRECISION) (SY per PT)
  // Simplified: 
  // - Buy: price = (exchangeRate * pyIndex) / PRECISION
  // - Sell: price = (PRECISION * PRECISION) / (exchangeRate * pyIndex)

  if (direction === 'buy') {
    // Price = PT per SY
    const price = (exchangeRate * pyIndex) / PRECISION;
    if (ptConfig.debug && price === 0n) {
      console.log(`[Limit Order Price] Buy price is 0: exchangeRate=${exchangeRate.toString()}, pyIndex=${pyIndex.toString()}`);
    }
    return price;
  } else {
    // Price = SY per PT
    // Formula: price = PRECISION / (exchangeRate * pyIndex / PRECISION)
    // = (PRECISION * PRECISION) / (exchangeRate * pyIndex)
    const denominator = exchangeRate * pyIndex;
    if (denominator === 0n) {
      if (ptConfig.debug) {
        console.log(`[Limit Order Price] Sell denominator is 0: exchangeRate=${exchangeRate.toString()}, pyIndex=${pyIndex.toString()}`);
      }
      return 0n;
    }

    // Calculate price = (PRECISION * PRECISION) / denominator
    // If denominator > PRECISION * PRECISION, price will be < 1, which rounds to 0
    // In this case, the order gives very little SY per PT, so it's not profitable
    // But we still need to calculate it correctly for comparison

    // Use: price = (PRECISION * PRECISION) / denominator
    // This can be 0 if denominator is too large, which is correct - order is not profitable
    const price = (PRECISION * PRECISION) / denominator;

    if (ptConfig.debug && price === 0n) {
      console.log(`[Limit Order Price] Sell price is 0 (denominator too large): exchangeRate=${exchangeRate.toString()}, pyIndex=${pyIndex.toString()}, denominator=${denominator.toString()}, PRECISION^2=${(PRECISION * PRECISION).toString()}`);
    }
    return price;
  }
}

// Fetch limit orders from Pendle API
async function fetchPendleLimitOrders(params: {
  market: string;
  yt: string;
  type: number; // 0 = SY_FOR_PT, 1 = PT_FOR_SY, 2 = SY_FOR_YT, 3 = YT_FOR_SY
  chainId?: number; // Default: 1 (Ethereum mainnet)
  sortBy?: string; // Default: "Implied Rate"
  sortOrder?: 'asc' | 'desc'; // Default: "desc"
}): Promise<LimitOrderData> {
  const url = new URL('https://api-v2.pendle.finance/limit-order/v1/takers/limit-orders');
  url.searchParams.set('chainId', String(params.chainId || 1));
  url.searchParams.set('yt', params.yt);
  url.searchParams.set('type', String(params.type));
  url.searchParams.set('sortBy', params.sortBy || 'Implied Rate');
  url.searchParams.set('sortOrder', params.sortOrder || 'desc');
  url.searchParams.set('limit', '100'); // Request up to 100 orders (API default is 10)

  const response = await fetch(url.toString(), {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    let errorMessage = `Pendle API error: ${response.status} ${response.statusText}`;
    try {
      const errorData = JSON.parse(errorText);
      if (errorData.message) {
        errorMessage += ` - ${JSON.stringify(errorData.message)}`;
      }
    } catch {
      errorMessage += ` - ${errorText}`;
    }
    throw new Error(errorMessage);
  }

  const apiResponse = await response.json() as PendleApiResponse;

  if (ptConfig.debug) {
    console.log('[Pendle API] Raw response:', {
      total: apiResponse.total,
      limit: apiResponse.limit,
      skip: apiResponse.skip,
      resultsCount: apiResponse.results?.length || 0,
      url: url.toString(),
      firstResult: apiResponse.results?.[0] ? Object.keys(apiResponse.results[0]) : 'No results',
    });
  }

  // Convert API response to LimitOrderData format
  // API returns results with structure: { order: {...}, makingAmount: "...", ... }
  // We need to convert to FillOrderParams format
  const results = apiResponse.results || [];

  if (ptConfig.debug && results.length > 0) {
    console.log('[Pendle API] First result structure:', JSON.stringify(results[0], null, 2).substring(0, 500));
  }

  // Convert PendleApiResult[] to FillOrderParams[]
  const fillOrderParams: FillOrderParams[] = results.map((result) => {
    const apiOrder = result.order;
    return {
      order: {
        salt: apiOrder.salt,
        expiry: apiOrder.expiry,
        nonce: apiOrder.nonce,
        orderType: apiOrder.type,
        token: apiOrder.token,
        YT: apiOrder.yt,
        maker: apiOrder.maker,
        receiver: apiOrder.receiver,
        makingAmount: apiOrder.makingAmount,
        lnImpliedRate: apiOrder.lnImpliedRate,
        failSafeRate: apiOrder.failSafeRate,
        permit: apiOrder.permit || '0x',
      },
      signature: apiOrder.signature,
      makingAmount: result.makingAmount || apiOrder.makingAmount,
    };
  });

  const limitOrderData: LimitOrderData = {
    limitRouter: '', // Will be set from API response or fallback
    epsSkipMarket: 0n,
    normalFills: fillOrderParams,
    flashFills: [], // API doesn't distinguish between normal and flash fills, we'll filter later if needed
    optData: '0x',
  };

  return limitOrderData;
}

// Get current block timestamp
async function getCurrentBlockTimestamp(): Promise<bigint> {
  const rpcBody = {
    jsonrpc: '2.0',
    id: 1,
    method: 'eth_getBlockByNumber',
    params: ['latest', false],
  };

  const resp = await fetch(ptConfig.alchemy.rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(rpcBody),
  });

  const json = await resp.json() as any;
  if (json?.error) {
    throw new Error(`RPC error: ${json.error?.message || 'Unknown error'}`);
  }

  const block = json?.result;
  if (!block?.timestamp) {
    throw new Error('Failed to get block timestamp');
  }

  return BigInt(block.timestamp);
}

// Batch check nonces for multiple makers
async function batchCheckNonces(limitRouterAddress: Address, makers: Address[]): Promise<Map<Address, bigint>> {
  const uniqueMakers = Array.from(new Set(makers.map(m => m.toLowerCase())));
  const nonceDataArray = uniqueMakers.map(maker =>
    encodeFunctionData({
      abi: pendleLimitRouterAbi,
      functionName: 'nonce',
      args: [maker as Address],
    })
  );

  const bundles: EthCallManyBundle[] = [
    {
      transactions: uniqueMakers.map((maker, idx) => ({
        from: ZERO_ADDRESS,
        to: limitRouterAddress,
        data: nonceDataArray[idx],
      })),
    },
  ];

  const rpcJson = await ethCallMany(bundles);
  const bundleResult = rpcJson?.result?.[0];
  const results = Array.isArray(bundleResult) ? bundleResult : [];

  const nonceMap = new Map<Address, bigint>();
  uniqueMakers.forEach((maker, idx) => {
    const result = results[idx];
    if (result && typeof result === 'object' && (result as any).error) {
      // If nonce check fails, assume 0
      nonceMap.set(maker as Address, 0n);
      return;
    }

    const output = extractEthCallManyOutput(result);
    if (output) {
      try {
        const decoded = decodeFunctionResult({
          abi: pendleLimitRouterAbi,
          functionName: 'nonce',
          data: output,
        }) as unknown as bigint;
        nonceMap.set(maker as Address, decoded);
      } catch {
        nonceMap.set(maker as Address, 0n);
      }
    } else {
      nonceMap.set(maker as Address, 0n);
    }
  });

  return nonceMap;
}

// Batch check signatures for multiple orders (much faster than sequential)
async function batchCheckOrderSignatures(
  limitRouterAddress: Address,
  orders: Array<{ order: Order; signature: string }>
): Promise<Map<number, { orderHash: Hex; remainingAmount: bigint; filledAmount: bigint } | null>> {
  if (orders.length === 0) {
    return new Map();
  }

  const results = new Map<number, { orderHash: Hex; remainingAmount: bigint; filledAmount: bigint } | null>();

  // Prepare all checkSig calls
  const transactions = orders.map(({ order, signature }) => {
    const orderTuple = {
      salt: normalizeBigInt(order.salt),
      expiry: normalizeBigInt(order.expiry),
      nonce: normalizeBigInt(order.nonce),
      orderType: order.orderType,
      token: normalizeAddress(order.token),
      YT: normalizeAddress(order.YT),
      maker: normalizeAddress(order.maker),
      receiver: normalizeAddress(order.receiver),
      makingAmount: normalizeBigInt(order.makingAmount),
      lnImpliedRate: normalizeBigInt(order.lnImpliedRate),
      failSafeRate: normalizeBigInt(order.failSafeRate),
      permit: (order.permit || '0x') as Hex,
    };

    const checkSigData = encodeFunctionData({
      abi: pendleLimitRouterAbi,
      functionName: '_checkSig',
      args: [orderTuple, signature as Hex],
    });

    return { from: ZERO_ADDRESS, to: limitRouterAddress, data: checkSigData };
  });

  // Execute batch call
  const bundles: EthCallManyBundle[] = [
    {
      transactions,
    },
  ];

  try {
    const rpcJson = await ethCallMany(bundles);
    const bundleResult = rpcJson?.result?.[0];
    const bundleResults = Array.isArray(bundleResult) ? bundleResult : [];

    // Process results
    for (let i = 0; i < orders.length; i++) {
      const result = bundleResults[i];

      if (result && typeof result === 'object' && (result as any).error) {
        results.set(i, null);
        continue;
      }

      const output = extractEthCallManyOutput(result);
      if (!output) {
        results.set(i, null);
        continue;
      }

      try {
        const decoded = decodeFunctionResult({
          abi: pendleLimitRouterAbi,
          functionName: '_checkSig',
          data: output,
        }) as unknown as readonly [Hex, bigint, bigint];

        results.set(i, {
          orderHash: decoded[0],
          remainingAmount: decoded[1],
          filledAmount: decoded[2],
        });
      } catch {
        results.set(i, null);
      }
    }
  } catch (error) {
    // If batch fails, mark all as null
    for (let i = 0; i < orders.length; i++) {
      results.set(i, null);
    }
  }

  return results;
}

// Check signature and get remaining amount for a single order (kept for backward compatibility)
async function checkOrderSignature(
  limitRouterAddress: Address,
  order: Order,
  signature: string
): Promise<{ orderHash: Hex; remainingAmount: bigint; filledAmount: bigint } | null> {
  const results = await batchCheckOrderSignatures(limitRouterAddress, [{ order, signature }]);
  return results.get(0) ?? null;
}

// Filter fills (normalFills or flashFills)
async function filterFills(
  fills: FillOrderParams[],
  limitRouterAddress: Address,
  expectedOrderType: number,
  expectedYT: Address,
  currentTimestamp: bigint,
  nonceMap: Map<Address, bigint>
): Promise<{ valid: FillOrderParams[]; stats: FilterStats }> {
  const stats: FilterStats = {
    invalidSignature: 0,
    expired: 0,
    wrongNonce: 0,
    zeroRemaining: 0,
    wrongType: 0,
    worseThanMarket: 0,
  };

  const valid: FillOrderParams[] = [];

  if (fills.length === 0) {
    return { valid, stats };
  }

  // Step 1: Fast local filters (type, expiry, nonce) - no RPC calls
  const preFiltered: Array<{ fill: FillOrderParams; index: number }> = [];

  fills.forEach((fill, index) => {
    const order = fill.order;

    // Filter 1: Check order type and YT
    if (order.orderType !== expectedOrderType || normalizeAddress(order.YT) !== normalizeAddress(expectedYT)) {
      stats.wrongType++;
      return;
    }

    // Filter 2: Check expiry
    const expiry = normalizeBigInt(order.expiry);
    if (expiry <= currentTimestamp) {
      stats.expired++;
      return;
    }

    // Filter 3: Check nonce
    const maker = normalizeAddress(order.maker);
    const currentNonce = nonceMap.get(maker) ?? 0n;
    const orderNonce = normalizeBigInt(order.nonce);
    if (orderNonce < currentNonce) {
      stats.wrongNonce++;
      return;
    }

    // Passed fast filters, will check signature in batch
    preFiltered.push({ fill, index });
  });

  if (preFiltered.length === 0) {
    return { valid, stats };
  }

  // Step 2: Batch check signatures for all pre-filtered orders (much faster)
  const ordersToCheck = preFiltered.map(({ fill }) => ({
    order: fill.order,
    signature: fill.signature,
  }));

  const sigResults = await batchCheckOrderSignatures(limitRouterAddress, ordersToCheck);

  // Step 3: Process signature results
  preFiltered.forEach(({ fill, index }) => {
    const sigResult = sigResults.get(index);

    if (!sigResult) {
      stats.invalidSignature++;
      return;
    }

    if (sigResult.remainingAmount === 0n) {
      stats.zeroRemaining++;
      return;
    }

    // All checks passed
    valid.push(fill);
  });

  return { valid, stats };
}

// Calculate AMM output for remaining amount
async function calculateAmmOutputForRemaining(
  marketAddress: Address,
  remainingAmount: bigint,
  direction: 'buy' | 'sell',
  SY: Address,
  PT: Address
): Promise<bigint> {
  if (remainingAmount === 0n) {
    return 0n;
  }
  return await calculateMarketSwapOutput(marketAddress, remainingAmount, direction, SY, PT);
}

// Calculate limit order output for given input amount
// For limit orders, output is proportional to input (price is constant)
function calculateLimitOrderOutput(
  order: Order,
  inputAmount: bigint,
  pyIndex: bigint,
  currentTimestamp: bigint,
  direction: 'buy' | 'sell'
): bigint {
  const orderPrice = calculateLimitOrderPrice(order, pyIndex, currentTimestamp, direction);
  if (orderPrice === 0n) {
    return 0n;
  }
  // Output = input * price / PRECISION
  return (inputAmount * orderPrice) / PRECISION;
}

// Binary search for optimal partial fill amount
// Returns the maximum amount from order that is better than AMM
async function findOptimalPartialFill(
  fill: FillOrderParams,
  remainingAmount: bigint,
  direction: 'buy' | 'sell',
  marketAddress: Address,
  SY: Address,
  PT: Address,
  pyIndex: bigint,
  currentTimestamp: bigint,
  orderIndex?: number
): Promise<bigint> {
  const orderMakingAmount = normalizeBigInt(fill.makingAmount);

  // Calculate order output for full order
  const orderOutputFull = calculateLimitOrderOutput(fill.order, orderMakingAmount, pyIndex, currentTimestamp, direction);

  if (orderOutputFull === 0n) {
    if (ptConfig.debug && orderIndex !== undefined) {
      console.log(`[Order ${orderIndex}] Invalid order (output = 0)`);
    }
    return 0n; // Invalid order
  }

  // Check if full order (if smaller than remaining) is better than AMM
  if (orderMakingAmount <= remainingAmount) {
    const ammOutput = await calculateAmmOutputForRemaining(marketAddress, orderMakingAmount, direction, SY, PT);
    const minOutput = (ammOutput * 999n) / 1000n; // 0.1% buffer (order must give at least 99.9% of AMM)

    if (ptConfig.debug && orderIndex !== undefined) {
      console.log(`[Order ${orderIndex}] Full order comparison:`);
      console.log(`  Input: ${orderMakingAmount.toString()} ${direction === 'buy' ? 'SY' : 'PT'}`);
      console.log(`  Limit Order Output: ${orderOutputFull.toString()} ${direction === 'buy' ? 'PT' : 'SY'}`);
      console.log(`  AMM Output: ${ammOutput.toString()} ${direction === 'buy' ? 'PT' : 'SY'}`);
      console.log(`  Min Required (99.9%): ${minOutput.toString()}`);
      console.log(`  Decision: ${orderOutputFull >= minOutput && ammOutput > 0n ? '✅ TAKE FULL ORDER' : '❌ NOT BETTER THAN AMM'}`);
    }

    if (orderOutputFull >= minOutput && ammOutput > 0n) {
      return orderMakingAmount; // Take full order
    }
    return 0n; // Not better than AMM
  }

  // Order is larger than remaining amount - compare outputs for remaining amount
  const orderOutputForRemaining = calculateLimitOrderOutput(fill.order, remainingAmount, pyIndex, currentTimestamp, direction);
  const ammOutputForRemaining = await calculateAmmOutputForRemaining(marketAddress, remainingAmount, direction, SY, PT);
  const minOutputForRemaining = (ammOutputForRemaining * 999n) / 1000n; // 0.1% buffer

  if (ptConfig.debug && orderIndex !== undefined) {
    console.log(`[Order ${orderIndex}] Partial order comparison (order larger than remaining):`);
    console.log(`  Order Size: ${orderMakingAmount.toString()}, Remaining: ${remainingAmount.toString()}`);
    console.log(`  Input: ${remainingAmount.toString()} ${direction === 'buy' ? 'SY' : 'PT'}`);
    console.log(`  Limit Order Output: ${orderOutputForRemaining.toString()} ${direction === 'buy' ? 'PT' : 'SY'}`);
    console.log(`  AMM Output: ${ammOutputForRemaining.toString()} ${direction === 'buy' ? 'PT' : 'SY'}`);
    console.log(`  Min Required (99.9%): ${minOutputForRemaining.toString()}`);
    console.log(`  Decision: ${orderOutputForRemaining >= minOutputForRemaining && ammOutputForRemaining > 0n ? `✅ TAKE PARTIAL (${remainingAmount.toString()})` : '❌ NOT BETTER THAN AMM'}`);
  }

  if (orderOutputForRemaining < minOutputForRemaining || ammOutputForRemaining === 0n) {
    return 0n; // Even for remaining amount, order is not better
  }

  // Order is better for remaining amount, take remainingAmount
  return remainingAmount;
}

// Prioritize and limit orders by comparing each with AMM for remaining amount
// Stops when an order is not better than AMM
async function prioritizeOrdersByAmmComparison(
  fills: FillOrderParams[],
  direction: 'buy' | 'sell',
  maxOrders: number,
  amountIn: bigint,
  marketAddress: Address,
  SY: Address,
  PT: Address,
  pyIndex: bigint,
  currentTimestamp: bigint
): Promise<{ selected: FillOrderParams[]; worseThanMarket: number }> {
  if (ptConfig.debug) {
    console.log(`\n[Order Selection] Starting AMM comparison:`);
    console.log(`  Direction: ${direction}`);
    console.log(`  Total Orders: ${fills.length}`);
    console.log(`  Amount In: ${amountIn.toString()} ${direction === 'buy' ? 'SY' : 'PT'}`);
    console.log(`  Max Orders: ${maxOrders}`);
  }

  // Sort by lnImpliedRate
  const sorted = [...fills].sort((a, b) => {
    const rateA = normalizeBigInt(a.order.lnImpliedRate);
    const rateB = normalizeBigInt(b.order.lnImpliedRate);
    if (direction === 'buy') {
      // For buy: higher rate = better price
      return rateB > rateA ? 1 : rateB < rateA ? -1 : 0;
    } else {
      // For sell: lower rate = better price
      return rateA > rateB ? 1 : rateA < rateB ? -1 : 0;
    }
  });

  const selected: FillOrderParams[] = [];
  let remainingAmount = amountIn;
  let worseThanMarket = 0;

  for (let i = 0; i < sorted.length; i++) {
    const fill = sorted[i];

    if (selected.length >= maxOrders || remainingAmount === 0n) {
      if (ptConfig.debug) {
        console.log(`[Order Selection] Stopping: maxOrders=${maxOrders} reached or remainingAmount=0`);
      }
      break;
    }

    const orderMakingAmount = normalizeBigInt(fill.makingAmount);

    // Determine comparison amount (min of order size and remaining)
    const comparisonAmount = orderMakingAmount < remainingAmount ? orderMakingAmount : remainingAmount;

    if (ptConfig.debug) {
      console.log(`\n[Order ${i}] Processing order:`);
      console.log(`  Order Size: ${orderMakingAmount.toString()}`);
      console.log(`  Remaining Amount: ${remainingAmount.toString()}`);
      console.log(`  Comparison Amount: ${comparisonAmount.toString()}`);
    }

    // Calculate order output for comparison amount
    const orderOutput = calculateLimitOrderOutput(fill.order, comparisonAmount, pyIndex, currentTimestamp, direction);

    if (orderOutput === 0n) {
      if (ptConfig.debug) {
        console.log(`[Order ${i}] ❌ Invalid order (output = 0), skipping`);
      }
      worseThanMarket++;
      continue;
    }

    // Calculate AMM output for same amount
    const ammOutput = await calculateAmmOutputForRemaining(marketAddress, comparisonAmount, direction, SY, PT);

    if (ammOutput === 0n) {
      if (ptConfig.debug) {
        console.log(`[Order ${i}] ❌ AMM calculation failed, skipping`);
      }
      worseThanMarket++;
      continue;
    }

    // Add 0.1% buffer to account for gas costs (order must give at least 99.9% of AMM output)
    const minOutput = (ammOutput * 999n) / 1000n;

    if (ptConfig.debug) {
      console.log(`[Order ${i}] Comparison:`);
      console.log(`  Input: ${comparisonAmount.toString()} ${direction === 'buy' ? 'SY' : 'PT'}`);
      console.log(`  Limit Order Output: ${orderOutput.toString()} ${direction === 'buy' ? 'PT' : 'SY'}`);
      console.log(`  AMM Output: ${ammOutput.toString()} ${direction === 'buy' ? 'PT' : 'SY'}`);
      console.log(`  Min Required (99.9%): ${minOutput.toString()}`);
      console.log(`  Better: ${orderOutput >= minOutput ? 'YES' : 'NO'}`);
    }

    if (orderOutput < minOutput) {
      // Order is not better than AMM, stop here
      if (ptConfig.debug) {
        console.log(`[Order ${i}] ❌ NOT BETTER THAN AMM - stopping selection`);
      }
      worseThanMarket++;
      break;
    }

    // Order is better than AMM
    if (orderMakingAmount <= remainingAmount) {
      // Take full order
      if (ptConfig.debug) {
        console.log(`[Order ${i}] ✅ TAKING FULL ORDER: ${orderMakingAmount.toString()}`);
      }
      selected.push(fill);
      remainingAmount -= orderMakingAmount;
    } else {
      // Try to find optimal partial fill
      const partialAmount = await findOptimalPartialFill(
        fill,
        remainingAmount,
        direction,
        marketAddress,
        SY,
        PT,
        pyIndex,
        currentTimestamp,
        i
      );

      if (partialAmount > 0n) {
        // Create partial fill
        if (ptConfig.debug) {
          console.log(`[Order ${i}] ✅ TAKING PARTIAL ORDER: ${partialAmount.toString()} (from ${orderMakingAmount.toString()})`);
        }
        const partialFill: FillOrderParams = {
          ...fill,
          makingAmount: partialAmount.toString(),
        };
        selected.push(partialFill);
        remainingAmount -= partialAmount;
      } else {
        // Partial fill is not better than AMM
        if (ptConfig.debug) {
          console.log(`[Order ${i}] ❌ PARTIAL FILL NOT BETTER - stopping selection`);
        }
        worseThanMarket++;
        break;
      }
    }
  }

  if (ptConfig.debug) {
    console.log(`\n[Order Selection] Completed:`);
    console.log(`  Selected Orders: ${selected.length}`);
    console.log(`  Remaining Amount: ${remainingAmount.toString()} ${direction === 'buy' ? 'SY' : 'PT'}`);
    console.log(`  Worse Than Market: ${worseThanMarket}`);
    if (selected.length > 0) {
      const totalSelected = selected.reduce((sum, fill) => sum + normalizeBigInt(fill.makingAmount), 0n);
      console.log(`  Total Selected Amount: ${totalSelected.toString()}`);
    }
  }

  return { selected, worseThanMarket };
}

// Legacy function for backward compatibility (simplified version)
function prioritizeAndLimitOrders(
  fills: FillOrderParams[],
  direction: 'buy' | 'sell',
  maxOrders: number,
  amountIn: bigint
): FillOrderParams[] {
  // Sort by lnImpliedRate
  const sorted = [...fills].sort((a, b) => {
    const rateA = normalizeBigInt(a.order.lnImpliedRate);
    const rateB = normalizeBigInt(b.order.lnImpliedRate);
    if (direction === 'buy') {
      // For buy: higher rate = better price
      return rateB > rateA ? 1 : rateB < rateA ? -1 : 0;
    } else {
      // For sell: lower rate = better price
      return rateA > rateB ? 1 : rateA < rateB ? -1 : 0;
    }
  });

  // Select orders until we have enough volume (with 20% buffer) or reach maxOrders
  const selected: FillOrderParams[] = [];
  let totalAmount = 0n;
  const targetAmount = (amountIn * 120n) / 100n; // 120% buffer (20% extra) to ensure we have enough

  for (const fill of sorted) {
    if (selected.length >= maxOrders) {
      break;
    }

    const makingAmount = normalizeBigInt(fill.makingAmount);
    selected.push(fill);
    totalAmount += makingAmount;

    // Stop if we've reached the target amount (we have enough volume)
    if (totalAmount >= targetAmount) {
      break;
    }
  }

  return selected;
}

// Encode LimitOrderData to bytes
function encodeLimitOrderData(data: LimitOrderData): Hex {
  // Encode Order struct as object (not array) for proper tuple encoding
  const encodeOrder = (order: Order) => {
    return {
      salt: normalizeBigInt(order.salt),
      expiry: normalizeBigInt(order.expiry),
      nonce: normalizeBigInt(order.nonce),
      orderType: order.orderType,
      token: normalizeAddress(order.token),
      YT: normalizeAddress(order.YT),
      maker: normalizeAddress(order.maker),
      receiver: normalizeAddress(order.receiver),
      makingAmount: normalizeBigInt(order.makingAmount),
      lnImpliedRate: normalizeBigInt(order.lnImpliedRate),
      failSafeRate: normalizeBigInt(order.failSafeRate),
      permit: (order.permit || '0x') as Hex,
    };
  };

  // Encode FillOrderParams struct as object
  const encodeFillOrderParams = (fill: FillOrderParams) => {
    return {
      order: encodeOrder(fill.order),
      signature: (fill.signature || '0x') as Hex,
      makingAmount: normalizeBigInt(fill.makingAmount),
    };
  };

  // Prepare LimitOrderData structure
  const limitOrderDataTuple = {
    limitRouter: normalizeAddress(data.limitRouter),
    epsSkipMarket: normalizeBigInt(data.epsSkipMarket),
    normalFills: data.normalFills.map(encodeFillOrderParams),
    flashFills: data.flashFills.map(encodeFillOrderParams),
    optData: (data.optData || '0x') as Hex,
  };

  // Use encodeFunctionData with a temporary function signature to encode the complex structure
  // This is a workaround for parseAbiParameters limitations with very complex nested tuples
  // We create a temporary ABI function that accepts our structure and encode the data as function parameters
  const tempAbi = [
    {
      name: 'tempEncode',
      type: 'function',
      stateMutability: 'pure',
      inputs: [
        {
          name: 'data',
          type: 'tuple',
          components: [
            { name: 'limitRouter', type: 'address' },
            { name: 'epsSkipMarket', type: 'uint256' },
            {
              name: 'normalFills',
              type: 'tuple[]',
              components: [
                {
                  name: 'order',
                  type: 'tuple',
                  components: [
                    { name: 'salt', type: 'uint256' },
                    { name: 'expiry', type: 'uint256' },
                    { name: 'nonce', type: 'uint256' },
                    { name: 'orderType', type: 'uint8' },
                    { name: 'token', type: 'address' },
                    { name: 'YT', type: 'address' },
                    { name: 'maker', type: 'address' },
                    { name: 'receiver', type: 'address' },
                    { name: 'makingAmount', type: 'uint256' },
                    { name: 'lnImpliedRate', type: 'uint256' },
                    { name: 'failSafeRate', type: 'uint256' },
                    { name: 'permit', type: 'bytes' },
                  ],
                },
                { name: 'signature', type: 'bytes' },
                { name: 'makingAmount', type: 'uint256' },
              ],
            },
            {
              name: 'flashFills',
              type: 'tuple[]',
              components: [
                {
                  name: 'order',
                  type: 'tuple',
                  components: [
                    { name: 'salt', type: 'uint256' },
                    { name: 'expiry', type: 'uint256' },
                    { name: 'nonce', type: 'uint256' },
                    { name: 'orderType', type: 'uint8' },
                    { name: 'token', type: 'address' },
                    { name: 'YT', type: 'address' },
                    { name: 'maker', type: 'address' },
                    { name: 'receiver', type: 'address' },
                    { name: 'makingAmount', type: 'uint256' },
                    { name: 'lnImpliedRate', type: 'uint256' },
                    { name: 'failSafeRate', type: 'uint256' },
                    { name: 'permit', type: 'bytes' },
                  ],
                },
                { name: 'signature', type: 'bytes' },
                { name: 'makingAmount', type: 'uint256' },
              ],
            },
            { name: 'optData', type: 'bytes' },
          ],
        },
      ],
      outputs: [],
    },
  ] as const;

  try {
    const encoded = encodeFunctionData({
      abi: tempAbi,
      functionName: 'tempEncode',
      args: [limitOrderDataTuple as any],
    });

    // Remove the function selector (first 4 bytes) to get just the encoded parameters
    return encoded.slice(10) as Hex; // 0x + 4 bytes selector = 10 chars
  } catch (error) {
    throw new Error(`Failed to encode LimitOrderData: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

// Helper functions for prepare-limit-orders endpoint

function validatePrepareLimitOrdersRequest(body: any):
  | { valid: true; market: Address; amountIn: string; direction: 'buy' | 'sell' }
  | { valid: false; error: string } {
  if (!body.market) {
    return { valid: false, error: 'Missing market' };
  }
  if (!body.amountIn) {
    return { valid: false, error: 'Missing amountIn' };
  }
  if (!body.direction || (body.direction !== 'buy' && body.direction !== 'sell')) {
    return { valid: false, error: 'Invalid direction (must be "buy" or "sell")' };
  }
  if (!isAddress(body.market)) {
    return { valid: false, error: 'Invalid market address' };
  }
  return { valid: true, market: body.market as Address, amountIn: body.amountIn, direction: body.direction };
}

async function getLimitRouterAddressSafe(pendleLimitOrderData: LimitOrderData): Promise<Address> {
  // Try multiple methods: from API response, from contract, from env variable, or fallback
  if (pendleLimitOrderData.limitRouter && isAddress(pendleLimitOrderData.limitRouter)) {
    return pendleLimitOrderData.limitRouter as Address;
  }

  const fromContract = await getLimitRouterAddress(1);
  if (fromContract) {
    if (ptConfig.debug) {
      console.log('[Pendle] Got limitRouter address from contract:', fromContract);
    }
    return fromContract;
  }

  const fromEnv = getPendleLimitRouterAddress(1);
  if (fromEnv && fromEnv !== ZERO_ADDRESS) {
    if (ptConfig.debug) {
      console.log('[Pendle] Got limitRouter address from environment variable');
    }
    return fromEnv;
  }

  const fallback = PENDLE_LIMIT_ROUTER_ADDRESSES[1];
  if (!fallback || fallback === ZERO_ADDRESS) {
    throw new Error('Limit router address not found. Tried: API response, Pendle Router contract, environment variable. Please set PENDLE_LIMIT_ROUTER_ADDRESS environment variable with the correct address for Ethereum mainnet.');
  }

  return fallback;
}

function calculateTotalFilteredOut(
  normalFillsStats: FilterStats,
  flashFillsStats: FilterStats,
  normalFillsWorseThanMarket: number,
  flashFillsWorseThanMarket: number
) {
  return {
    invalidSignature: normalFillsStats.invalidSignature + flashFillsStats.invalidSignature,
    expired: normalFillsStats.expired + flashFillsStats.expired,
    wrongNonce: normalFillsStats.wrongNonce + flashFillsStats.wrongNonce,
    zeroRemaining: normalFillsStats.zeroRemaining + flashFillsStats.zeroRemaining,
    wrongType: normalFillsStats.wrongType + flashFillsStats.wrongType,
    worseThanMarket: normalFillsWorseThanMarket + flashFillsWorseThanMarket,
    total: normalFillsStats.invalidSignature +
      normalFillsStats.expired +
      normalFillsStats.wrongNonce +
      normalFillsStats.zeroRemaining +
      normalFillsStats.wrongType +
      normalFillsWorseThanMarket +
      flashFillsStats.invalidSignature +
      flashFillsStats.expired +
      flashFillsStats.wrongNonce +
      flashFillsStats.zeroRemaining +
      flashFillsStats.wrongType +
      flashFillsWorseThanMarket,
  };
}

function createEmptyResponse(filteredOut: ReturnType<typeof calculateTotalFilteredOut>) {
  return {
    success: true,
    data: {
      encodedLimitOrderData: '0x',
      ordersCount: { normalFills: 0, flashFills: 0, total: 0 },
      filteredOut,
    },
  };
}

async function selectOrdersWithAmmComparison(
  normalFillsResult: { valid: FillOrderParams[]; stats: FilterStats },
  flashFillsResult: { valid: FillOrderParams[]; stats: FilterStats },
  direction: 'buy' | 'sell',
  amountInBigInt: bigint,
  maxOrders: number,
  market: Address,
  SY: Address,
  PT: Address,
  YT: Address,
  pyIndex: bigint,
  currentTimestamp: bigint
): Promise<{
  prioritizedNormalFills: FillOrderParams[];
  prioritizedFlashFills: FillOrderParams[];
  normalFillsWorseThanMarket: number;
  flashFillsWorseThanMarket: number;
}> {
  // Select normalFills by comparing each with AMM for remaining amount
  const normalFillsSelection = await prioritizeOrdersByAmmComparison(
    normalFillsResult.valid,
    direction,
    maxOrders,
    amountInBigInt,
    market,
    SY,
    PT,
    pyIndex,
    currentTimestamp
  );

  const prioritizedNormalFills = normalFillsSelection.selected;
  const normalFillsWorseThanMarket = normalFillsSelection.worseThanMarket;

  // Calculate remaining amount after normalFills
  const normalFillsTotal = prioritizedNormalFills.reduce((sum, fill) => sum + normalizeBigInt(fill.makingAmount), 0n);
  const remainingAmount = amountInBigInt > normalFillsTotal ? amountInBigInt - normalFillsTotal : 0n;
  const remainingSlots = Math.max(0, maxOrders - prioritizedNormalFills.length);

  // Select flashFills if there's remaining amount and slots
  let prioritizedFlashFills: FillOrderParams[] = [];
  let flashFillsWorseThanMarket = 0;

  if (remainingAmount > 0n && remainingSlots > 0) {
    const flashFillsSelection = await prioritizeOrdersByAmmComparison(
      flashFillsResult.valid,
      direction,
      remainingSlots,
      remainingAmount,
      market,
      SY,
      PT,
      pyIndex,
      currentTimestamp
    );
    prioritizedFlashFills = flashFillsSelection.selected;
    flashFillsWorseThanMarket = flashFillsSelection.worseThanMarket;
  }

  return {
    prioritizedNormalFills,
    prioritizedFlashFills,
    normalFillsWorseThanMarket,
    flashFillsWorseThanMarket,
  };
}

// POST /api/pendle/prepare-limit-orders
// Body: { market: "0x...", amountIn: "1000000000000000000", direction: "buy" | "sell" }
app.post('/api/pendle/prepare-limit-orders', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const body = req.body as PrepareLimitOrdersRequest;
    const validation = validatePrepareLimitOrdersRequest(body);

    if (!validation.valid) {
      res.status(400).json({ success: false, error: validation.error });
      return;
    }

    // TypeScript now knows validation.valid === true, so these fields are guaranteed
    const { market, amountIn, direction } = validation;
    const amountInBigInt = BigInt(amountIn);
    const maxOrders = 50;

    // Get market tokens
    const { SY, PT, YT } = await getTokensFromMarket(market);

    // Fetch limit orders from Pendle API
    const orderType = direction === 'buy' ? 2 : 3; // 2 = SY_FOR_YT (buy), 3 = YT_FOR_SY (sell)

    if (ptConfig.debug) {
      console.log('[Pendle API] Request params:', { market, yt: YT, type: orderType, direction, chainId: 1 });
    }

    let pendleLimitOrderData: LimitOrderData;
    try {
      pendleLimitOrderData = await fetchPendleLimitOrders({
        market,
        yt: YT,
        type: orderType,
        chainId: 1,
        sortBy: 'Implied Rate',
        sortOrder: direction === 'buy' ? 'desc' : 'asc',
      });

      if (ptConfig.debug) {
        console.log('[Pendle API] Response:', {
          normalFills: pendleLimitOrderData.normalFills?.length || 0,
          flashFills: pendleLimitOrderData.flashFills?.length || 0,
        });
      }
    } catch (error) {
      console.error('[Pendle API Error]', error);
      res.status(502).json({
        success: false,
        error: `Failed to fetch limit orders from Pendle API: ${error instanceof Error ? error.message : 'Unknown error'}`,
      });
      return;
    }

    // Check if orders exist
    const normalFills = pendleLimitOrderData.normalFills || [];
    const flashFills = pendleLimitOrderData.flashFills || [];

    if (normalFills.length === 0 && flashFills.length === 0) {
      res.status(200).json(createEmptyResponse({
        invalidSignature: 0,
        expired: 0,
        wrongNonce: 0,
        zeroRemaining: 0,
        wrongType: 0,
        worseThanMarket: 0,
        total: 0,
      }));
      return;
    }

    // Get limit router address
    let limitRouterAddress: Address;
    try {
      limitRouterAddress = await getLimitRouterAddressSafe(pendleLimitOrderData);
    } catch (error) {
      res.status(500).json({ success: false, error: error instanceof Error ? error.message : 'Unknown error' });
      return;
    }

    // Prepare for filtering
    const currentTimestamp = await getCurrentBlockTimestamp();
    const expectedOrderType = direction === 'buy' ? 2 : 3;
    const allMakers = new Set<Address>();
    [...normalFills, ...flashFills].forEach(fill => {
      allMakers.add(normalizeAddress(fill.order.maker));
    });
    const nonceMap = await batchCheckNonces(limitRouterAddress, Array.from(allMakers));

    // Filter fills
    const normalFillsResult = await filterFills(normalFills, limitRouterAddress, expectedOrderType, YT, currentTimestamp, nonceMap);
    const flashFillsResult = await filterFills(flashFills, limitRouterAddress, expectedOrderType, YT, currentTimestamp, nonceMap);

    // Get YT info for price calculation
    const { pyIndex } = await getYtInfo(YT, SY);

    if (ptConfig.debug) {
      console.log('[Order Selection] Starting sequential AMM comparison');
    }

    // Select orders by comparing with AMM
    const {
      prioritizedNormalFills,
      prioritizedFlashFills,
      normalFillsWorseThanMarket,
      flashFillsWorseThanMarket,
    } = await selectOrdersWithAmmComparison(
      normalFillsResult,
      flashFillsResult,
      direction,
      amountInBigInt,
      maxOrders,
      market,
      SY,
      PT,
      YT,
      pyIndex,
      currentTimestamp
    );

    // Update stats
    normalFillsResult.stats.worseThanMarket = normalFillsWorseThanMarket;
    flashFillsResult.stats.worseThanMarket = flashFillsWorseThanMarket;

    // If no orders selected, return empty data (will use AMM)
    if (prioritizedNormalFills.length === 0 && prioritizedFlashFills.length === 0) {
      const filteredOut = calculateTotalFilteredOut(
        normalFillsResult.stats,
        flashFillsResult.stats,
        normalFillsWorseThanMarket,
        flashFillsWorseThanMarket
      );
      res.status(200).json(createEmptyResponse(filteredOut));
      return;
    }

    // Prepare and encode limit order data
    const limitOrderData: LimitOrderData = {
      limitRouter: limitRouterAddress,
      epsSkipMarket: pendleLimitOrderData.epsSkipMarket || 0n,
      normalFills: prioritizedNormalFills,
      flashFills: prioritizedFlashFills,
      optData: pendleLimitOrderData.optData || '0x',
    };

    const encodedLimitOrderData = encodeLimitOrderData(limitOrderData);
    const filteredOut = calculateTotalFilteredOut(
      normalFillsResult.stats,
      flashFillsResult.stats,
      normalFillsWorseThanMarket,
      flashFillsWorseThanMarket
    );

    // Return response
    res.status(200).json({
      success: true,
      data: {
        encodedLimitOrderData,
        limitOrderData: {
          limitRouter: limitOrderData.limitRouter,
          epsSkipMarket: limitOrderData.epsSkipMarket.toString(),
          normalFills: limitOrderData.normalFills,
          flashFills: limitOrderData.flashFills,
          optData: limitOrderData.optData,
        },
        ordersCount: {
          normalFills: prioritizedNormalFills.length,
          flashFills: prioritizedFlashFills.length,
          total: prioritizedNormalFills.length + prioritizedFlashFills.length,
        },
        filteredOut,
      },
    });
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


