import express, { type NextFunction, type Request, type Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { decodeFunctionResult, encodeFunctionData, isAddress, parseAbi, decodeErrorResult, type Address, type Hex } from 'viem';
import { ptConfig } from './pt-config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const USDC_ADDRESS = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' as const satisfies Address;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as const satisfies Address;
// Empty EOA address used for token operations (tokens are transferred here from rich addresses)
const EMPTY_EOA = '0x1111111111111111111111111111111111111111' as const satisfies Address;

const MAX_UINT256 = (2n ** 256n) - 1n;

const erc20Abi = parseAbi([
  'function approve(address spender, uint256 amount) external returns (bool)',
  'function balanceOf(address account) external view returns (uint256)',
  'function transfer(address to, uint256 amount) external returns (bool)',
]);
const viewerAbi = parseAbi([
  'function simulatePtBuy(address from, address vault, uint256 strategyId, uint256 baseAssetAmount, bytes data) external returns (bool finished, uint256[] amounts)',
  'function simulatePtBuyBSLow(address from, address vault, uint256 strategyId, uint256 targetPtAmount, uint256 precisionBps, bytes memory data) external returns (bool finished, uint256 baseAssetAmount, uint256[] memory amounts)',
]);
const vaultAbi = parseAbi([
  'function availableLiquidity() external view returns (uint256)',
  'function previewBorrow(address forUser, uint256 strategyId, uint8 collateralType, uint256 collateralAmount, uint256 assetsToBorrow, bytes memory data) external returns (uint256[] memory assetsReceived)',
]);
const adapterAbi = parseAbi([
  'function TOKEN_IN() external view returns (address)',
  'function TOKEN_OUT() external view returns (address)',
  'function buy(uint256 amountIn, uint256 positionId, uint256 minAmountOut, bytes memory data) external returns (uint256 amountOut, bool finished)',
]);

// Mapping: TOKEN_IN address -> address that owns large amount of this token
// Loaded from token-holders.json file
let tokenInHolderMap: Record<Address, Address> = {};

try {
  const tokenHoldersPath = join(__dirname, '..', 'token-holders.json');
  const tokenHoldersData = readFileSync(tokenHoldersPath, 'utf-8');
  const parsed = JSON.parse(tokenHoldersData) as Record<string, string>;

  // Validate that all addresses are valid
  for (const [token, holder] of Object.entries(parsed)) {
    if (!isAddress(token)) {
      console.warn(`[Warning] Invalid token address in token-holders.json: ${token}`);
      continue;
    }
    if (!isAddress(holder)) {
      console.warn(`[Warning] Invalid holder address in token-holders.json for token ${token}: ${holder}`);
      continue;
    }
    tokenInHolderMap[token as Address] = holder as Address;
  }

  console.log(`[PT-API] Loaded ${Object.keys(tokenInHolderMap).length} token holder mappings from token-holders.json`);
} catch (err: any) {
  if (err.code === 'ENOENT') {
    console.warn('[PT-API] token-holders.json not found, using empty mapping');
  } else {
    console.error('[PT-API] Failed to load token-holders.json:', err.message);
    console.warn('[PT-API] Using empty mapping');
  }
}

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

  // If result is an array, try to extract from first element
  if (Array.isArray(result) && result.length > 0) {
    return extractEthCallManyOutput(result[0]);
  }

  const r = result as Record<string, unknown>;
  const candidates = [r.output, r.returnData, r.data, r.result, r.value];
  for (const c of candidates) {
    if (typeof c === 'string' && c.startsWith('0x')) return c as Hex;
  }
  return null;
};

const decodeAddress = (output: Hex, abi: typeof adapterAbi, functionName: 'TOKEN_IN' | 'TOKEN_OUT'): Address | null => {
  try {
    const decoded = decodeFunctionResult({
      abi,
      functionName,
      data: output,
    }) as unknown as Address;
    if (isAddress(decoded)) {
      return decoded;
    }
  } catch {
    // Fallback: parse address directly from hex (last 40 chars = 20 bytes)
    const addr = output.slice(-40);
    if (isAddress(`0x${addr}`)) {
      return `0x${addr}` as Address;
    }
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

// POST /simulateTokenSale
// Body: { adapters: ["0x...", "0x..."], amount: "123", data: "0x" (optional) }
// Also supports camelCase keys and query params for convenience.
app.all('/simulateTokenSale', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    if (req.method !== 'POST' && req.method !== 'GET') {
      res.status(405).json({ error: 'Method not allowed' });
      return;
    }

    const adaptersRaw = (req.body as any)?.adapters ?? (req.query as any)?.adapters;
    const amountRaw =
      pickString((req.body as any)?.amount) ??
      pickString((req.query as any)?.amount);

    const dataRaw =
      pickString((req.body as any)?.data) ??
      pickString((req.query as any)?.data) ??
      '0x';

    if (!adaptersRaw) {
      res.status(400).json({ error: 'Missing adapters' });
      return;
    }
    if (!amountRaw) {
      res.status(400).json({ error: 'Missing amount' });
      return;
    }

    let adapters: Address[];
    if (Array.isArray(adaptersRaw)) {
      adapters = adaptersRaw.map((a: any) => {
        const addr = typeof a === 'string' ? a : String(a);
        if (!isAddress(addr)) {
          throw new Error(`Invalid adapter address: ${addr}`);
        }
        return addr as Address;
      });
    } else if (typeof adaptersRaw === 'string') {
      // Try to parse as JSON array
      try {
        const parsed = JSON.parse(adaptersRaw);
        if (!Array.isArray(parsed)) {
          throw new Error('adapters must be an array');
        }
        adapters = parsed.map((a: any) => {
          const addr = typeof a === 'string' ? a : String(a);
          if (!isAddress(addr)) {
            throw new Error(`Invalid adapter address: ${addr}`);
          }
          return addr as Address;
        });
      } catch {
        res.status(400).json({ error: 'Invalid adapters format (must be array of addresses)' });
        return;
      }
    } else {
      res.status(400).json({ error: 'Invalid adapters format (must be array)' });
      return;
    }

    if (adapters.length === 0) {
      res.status(400).json({ error: 'adapters array cannot be empty' });
      return;
    }

    const amount = parseBigIntParam(amountRaw, 'amount');
    const positionId = 0n; // Always 0
    const minAmountOut = 0n; // Always 0

    let data: Hex = '0x' as Hex;
    if (dataRaw && dataRaw.startsWith('0x')) {
      data = dataRaw as Hex;
    } else if (dataRaw && dataRaw !== '0x') {
      res.status(400).json({ error: 'Invalid data (must be hex string starting with 0x)' });
      return;
    }

    // Step 1: Get TOKEN_IN and TOKEN_OUT for all adapters in one call
    const adapterTokensData: { tokenIn: Address; tokenOut: Address }[] = [];

    const tokenQueries: EthCallManyTx[] = [];
    for (const adapter of adapters) {
      tokenQueries.push(
        { from: ZERO_ADDRESS, to: adapter, data: encodeFunctionData({ abi: adapterAbi, functionName: 'TOKEN_IN', args: [] }) },
        { from: ZERO_ADDRESS, to: adapter, data: encodeFunctionData({ abi: adapterAbi, functionName: 'TOKEN_OUT', args: [] }) },
      );
    }

    const tokensBundle: EthCallManyBundle[] = [{ transactions: tokenQueries }];
    const tokensJson = await ethCallMany(tokensBundle);
    // eth_callMany returns result as array of arrays: [[{value: "0x..."}, {value: "0x..."}]]
    const tokensBundleResult = tokensJson?.result?.[0];
    const tokensResults = Array.isArray(tokensBundleResult) ? tokensBundleResult : [];

    // Extract TOKEN_IN for first adapter to check mapping (it's at index 0)
    const firstTokenInOutput = extractEthCallManyOutput(tokensResults[0]);
    if (!firstTokenInOutput) {
      res.status(502).json({ error: 'Failed to get TOKEN_IN from first adapter', raw: tokensJson?.result });
      return;
    }

    const firstTokenIn = decodeAddress(firstTokenInOutput, adapterAbi, 'TOKEN_IN');
    if (!firstTokenIn) {
      res.status(502).json({ error: 'Failed to decode TOKEN_IN address', raw: firstTokenInOutput });
      return;
    }

    // Check if firstTokenIn is in the mapping
    const tokenInHolder = tokenInHolderMap[firstTokenIn];
    if (!tokenInHolder) {
      res.status(400).json({
        error: `TOKEN_IN ${firstTokenIn} not found in tokenInHolderMap`,
        tokenIn: firstTokenIn,
      });
      return;
    }

    for (let i = 0; i < adapters.length; i++) {
      const tokenInOutput = extractEthCallManyOutput(tokensResults[i * 2]);
      const tokenOutOutput = extractEthCallManyOutput(tokensResults[i * 2 + 1]);

      if (!tokenInOutput || !tokenOutOutput) {
        res.status(502).json({ error: `Failed to get tokens for adapter ${i}`, raw: tokensResults });
        return;
      }

      const tokenIn = decodeAddress(tokenInOutput, adapterAbi, 'TOKEN_IN');
      const tokenOut = decodeAddress(tokenOutOutput, adapterAbi, 'TOKEN_OUT');

      if (!tokenIn || !tokenOut) {
        res.status(502).json({
          error: `Failed to decode tokens for adapter ${i}`,
          tokenInOutput,
          tokenOutOutput,
        });
        return;
      }

      adapterTokensData.push({ tokenIn, tokenOut });
    }

    // Step 3: Execute adapters sequentially, but in one eth_callMany bundle
    // This ensures state is preserved between adapters (tokens from previous buy are available for next)
    // However, we need to know amountOut from previous buy to use as amountIn for next
    // So we execute sequentially but in one bundle by building transactions dynamically
    const balanceChanges: Array<{ token: Address; change: string }> = [];
    const buyResults: Array<{ finished: boolean; amountOut: string }> = [];

    // We'll build transactions step by step, but execute in one bundle
    // For now, keep sequential execution but ensure we use correct amountOut from previous
    let currentAmountIn = amount;

    // Build all transactions for all adapters
    const allTransactions: EthCallManyTx[] = [];
    const adapterTxRanges: Array<{ start: number; end: number }> = [];

    for (let i = 0; i < adapters.length; i++) {
      const adapter = adapters[i];
      const { tokenIn, tokenOut } = adapterTokensData[i];

      const richTokenHolder = i === 0
        ? tokenInHolder
        : (tokenInHolderMap[tokenIn] || tokenInHolder);

      const startIdx = allTransactions.length;

      // Balance before tokenOut
      allTransactions.push({
        from: ZERO_ADDRESS,
        to: tokenOut,
        data: encodeFunctionData({
          abi: erc20Abi,
          functionName: 'balanceOf',
          args: [EMPTY_EOA],
        }),
      });

      // Balance before tokenIn
      allTransactions.push({
        from: ZERO_ADDRESS,
        to: tokenIn,
        data: encodeFunctionData({
          abi: erc20Abi,
          functionName: 'balanceOf',
          args: [EMPTY_EOA],
        }),
      });

      // Transfer: for first adapter from rich address, for intermediate from rich address of intermediate token
      if (i === 0) {
        allTransactions.push({
          from: richTokenHolder,
          to: tokenIn,
          data: encodeFunctionData({
            abi: erc20Abi,
            functionName: 'transfer',
            args: [EMPTY_EOA, currentAmountIn],
          }),
        });
      } else {
        // For intermediate adapters, transfer intermediate token from rich address
        // But we need to use amountOut from previous adapter, which we don't know yet
        // So we'll use a placeholder and update after first execution
        // Actually, we can't do this in one bundle - we need sequential execution
        // But the issue is state doesn't persist between bundles
        // Solution: use rich address holder for intermediate tokens too
        allTransactions.push({
          from: richTokenHolder,
          to: tokenIn,
          data: encodeFunctionData({
            abi: erc20Abi,
            functionName: 'transfer',
            args: [EMPTY_EOA, currentAmountIn], // This will be updated after we know amountOut
          }),
        });
      }

      // Approve
      allTransactions.push({
        from: EMPTY_EOA,
        to: tokenIn,
        data: encodeFunctionData({
          abi: erc20Abi,
          functionName: 'approve',
          args: [adapter, MAX_UINT256],
        }),
      });

      // Buy
      allTransactions.push({
        from: EMPTY_EOA,
        to: adapter,
        data: encodeFunctionData({
          abi: adapterAbi,
          functionName: 'buy',
          args: [currentAmountIn, positionId, minAmountOut, data],
        }),
      });

      // Balance after tokenIn
      allTransactions.push({
        from: ZERO_ADDRESS,
        to: tokenIn,
        data: encodeFunctionData({
          abi: erc20Abi,
          functionName: 'balanceOf',
          args: [EMPTY_EOA],
        }),
      });

      // Balance after tokenOut
      allTransactions.push({
        from: ZERO_ADDRESS,
        to: tokenOut,
        data: encodeFunctionData({
          abi: erc20Abi,
          functionName: 'balanceOf',
          args: [EMPTY_EOA],
        }),
      });

      adapterTxRanges.push({
        start: startIdx,
        end: allTransactions.length,
      });

      // We can't update currentAmountIn here because we don't know amountOut yet
      // So we'll need to execute sequentially or rebuild bundle after each adapter
    }

    // Actually, we can't use amountOut from previous buy in the same bundle
    // So we need to execute adapters sequentially, but the state won't persist
    // The solution: for intermediate adapters, use transfer from rich address holder
    // But we need to know the amount - we'll use amountOut from previous after extracting it

    // Execute adapters sequentially to get amountOut for next
    for (let i = 0; i < adapters.length; i++) {
      const adapter = adapters[i];
      const { tokenIn, tokenOut } = adapterTokensData[i];
      const richTokenHolder = i === 0
        ? tokenInHolder
        : (tokenInHolderMap[tokenIn] || tokenInHolder);

      // Build transactions for this adapter
      const adapterTransactions: EthCallManyTx[] = [];

      // Balance before tokenOut
      adapterTransactions.push({
        from: ZERO_ADDRESS,
        to: tokenOut,
        data: encodeFunctionData({
          abi: erc20Abi,
          functionName: 'balanceOf',
          args: [EMPTY_EOA],
        }),
      });

      // Balance before tokenIn
      adapterTransactions.push({
        from: ZERO_ADDRESS,
        to: tokenIn,
        data: encodeFunctionData({
          abi: erc20Abi,
          functionName: 'balanceOf',
          args: [EMPTY_EOA],
        }),
      });

      // Transfer: always from rich address holder (for first it's initial token, for intermediate it's intermediate token)
      adapterTransactions.push({
        from: richTokenHolder,
        to: tokenIn,
        data: encodeFunctionData({
          abi: erc20Abi,
          functionName: 'transfer',
          args: [EMPTY_EOA, currentAmountIn],
        }),
      });

      // Approve
      adapterTransactions.push({
        from: EMPTY_EOA,
        to: tokenIn,
        data: encodeFunctionData({
          abi: erc20Abi,
          functionName: 'approve',
          args: [adapter, MAX_UINT256],
        }),
      });

      // Buy
      adapterTransactions.push({
        from: EMPTY_EOA,
        to: adapter,
        data: encodeFunctionData({
          abi: adapterAbi,
          functionName: 'buy',
          args: [currentAmountIn, positionId, minAmountOut, data],
        }),
      });

      // Balance after tokenIn
      adapterTransactions.push({
        from: ZERO_ADDRESS,
        to: tokenIn,
        data: encodeFunctionData({
          abi: erc20Abi,
          functionName: 'balanceOf',
          args: [EMPTY_EOA],
        }),
      });

      // Balance after tokenOut
      adapterTransactions.push({
        from: ZERO_ADDRESS,
        to: tokenOut,
        data: encodeFunctionData({
          abi: erc20Abi,
          functionName: 'balanceOf',
          args: [EMPTY_EOA],
        }),
      });

      // Execute this adapter's transactions
      const adapterBundle: EthCallManyBundle[] = [{ transactions: adapterTransactions }];
      const adapterJson = await ethCallMany(adapterBundle);
      const adapterResults = Array.isArray(adapterJson?.result?.[0]) ? adapterJson.result[0] : [];

      // Check for errors
      for (let j = 0; j < adapterTransactions.length; j++) {
        const result = adapterResults[j];
        if (result && typeof result === 'object' && (result as any).error) {
          const err = (result as any).error;
          const msg = typeof err === 'string' ? err : (err?.message || 'Unknown error');
          console.error(`[Contract Error] Adapter ${i}, transaction ${j} failed:`, {
            error: err,
            message: msg,
            raw: result,
            adapter,
            tokenIn,
            tokenOut,
            amountIn: currentAmountIn.toString(),
          });
          res.status(502).json({
            error: `Adapter ${i} transaction ${j} failed: ${msg}`,
            raw: result,
            adapterIndex: i,
            transactionIndex: j,
          });
          return;
        }
      }

      // Extract balances and buy result
      // Structure: balanceBefore tokenOut (0), balanceBefore tokenIn (1), transfer (2), approve (3), buy (4), balanceAfter tokenIn (5), balanceAfter tokenOut (6)
      const beforeTokenOutOutput = extractEthCallManyOutput(adapterResults[0]);
      const beforeTokenOutBalance = beforeTokenOutOutput
        ? (decodeFunctionResult({ abi: erc20Abi, functionName: 'balanceOf', data: beforeTokenOutOutput }) as unknown as bigint)
        : 0n;

      const beforeTokenInOutput = extractEthCallManyOutput(adapterResults[1]);
      const beforeTokenInBalance = beforeTokenInOutput
        ? (decodeFunctionResult({ abi: erc20Abi, functionName: 'balanceOf', data: beforeTokenInOutput }) as unknown as bigint)
        : 0n;

      const buyOutput = extractEthCallManyOutput(adapterResults[4]);
      let amountOut = 0n;
      let finished = false;
      if (buyOutput) {
        try {
          const decoded = decodeFunctionResult({
            abi: adapterAbi,
            functionName: 'buy',
            data: buyOutput,
          }) as unknown as readonly [bigint, boolean];
          amountOut = decoded[0];
          finished = decoded[1];
        } catch (err) {
          console.error(`[Error] Failed to decode buy result for adapter ${i}:`, err);
        }
      }

      const afterTokenInOutput = extractEthCallManyOutput(adapterResults[5]);
      const afterTokenInBalance = afterTokenInOutput
        ? (decodeFunctionResult({ abi: erc20Abi, functionName: 'balanceOf', data: afterTokenInOutput }) as unknown as bigint)
        : 0n;

      const afterTokenOutOutput = extractEthCallManyOutput(adapterResults[6]);
      const afterTokenOutBalance = afterTokenOutOutput
        ? (decodeFunctionResult({ abi: erc20Abi, functionName: 'balanceOf', data: afterTokenOutOutput }) as unknown as bigint)
        : 0n;

      const tokenInChange = afterTokenInBalance - beforeTokenInBalance;
      const tokenOutChange = afterTokenOutBalance - beforeTokenOutBalance;

      if (ptConfig.debug) {
        console.log(`[simulateTokenSale] Adapter ${i}:`, {
          tokenIn,
          tokenOut,
          beforeTokenInBalance: beforeTokenInBalance.toString(),
          afterTokenInBalance: afterTokenInBalance.toString(),
          tokenInChange: tokenInChange.toString(),
          beforeTokenOutBalance: beforeTokenOutBalance.toString(),
          afterTokenOutBalance: afterTokenOutBalance.toString(),
          tokenOutChange: tokenOutChange.toString(),
          amountIn: currentAmountIn.toString(),
          amountOut: amountOut.toString(),
        });
      }

      balanceChanges.push({
        token: tokenOut,
        change: tokenOutChange.toString(),
      });

      buyResults.push({
        finished,
        amountOut: amountOut.toString(),
      });

      // Update currentAmountIn for next adapter
      currentAmountIn = amountOut;
    }

    res.status(200).json({
      balanceChanges,
      buyResults,
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


