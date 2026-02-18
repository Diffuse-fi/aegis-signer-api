import express, { type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import morgan from 'morgan';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import swaggerUi from 'swagger-ui-express';
import fs from 'fs';
import { isAddress, encodeAbiParameters, parseAbiParameters, type Hex, createPublicClient, http, parseAbi } from 'viem';
import { mainnet } from 'viem/chains';
import { signMessage, getSignerAddress } from './signer.js';
import { type SignRequest, type RedeemRequest } from './types.js';
import { config } from './config.js';

// Load swagger.json
const swaggerDocument = JSON.parse(fs.readFileSync(new URL('../swagger.json', import.meta.url), 'utf8'));

const app = express();

// Security: Helmet for security headers
// Configure helmet to allow CORS headers
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginEmbedderPolicy: false,
}));

// Trust proxy (needed for rate limit behind Nginx)
app.set('trust proxy', 1);

// Middleware
app.use(cors({
  origin: config.corsOrigin,
  credentials: false,
}));
app.use(morgan('dev'));
app.use(express.json({ limit: '10kb' })); // Limit body size to prevent DoS

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5000, // Limit each IP to 5000 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: 'Too many requests from this IP, please try again later.',
  validate: { xForwardedForHeader: false } // Disable X-Forwarded-For check if we trust proxy correctly
});
app.use(limiter);

// Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Health check
app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({ status: 'ok', signer: getSignerAddress() });
});

// Initialize viem public client
const publicClient = createPublicClient({
  chain: mainnet,
  transport: http(config.ethRpcUrl)
});

/**
 * Parses slippage value from string or number.
 * Supports both comma and dot as decimal separators.
 * @param value - Slippage value as string or number
 * @returns Parsed number
 * @throws Error if value cannot be parsed
 */
function parseSlippage(value: unknown): number {
  if (typeof value === 'number') {
    if (isNaN(value) || !isFinite(value)) {
      throw new Error('Invalid slippage (must be a finite number)');
    }
    return value;
  }

  if (typeof value === 'string') {
    // Replace comma with dot for parsing (supports both "1.5" and "1,5")
    const normalized = value.trim().replace(/,/g, '.');
    const parsed = parseFloat(normalized);

    if (isNaN(parsed) || !isFinite(parsed)) {
      throw new Error('Invalid slippage (must be a valid number)');
    }

    return parsed;
  }

  throw new Error('Invalid slippage (must be a number or numeric string)');
}

// Mint endpoint
app.post('/mint', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { collateral_amount, slippage, collateral_asset, adapter_address } = req.body as Partial<SignRequest>;

    // 1. Strict Input Validation
    if (!collateral_amount || typeof collateral_amount !== 'string' || !/^[1-9]\d*$/.test(collateral_amount)) {
      res.status(400).json({ error: 'Invalid collateral_amount (must be a positive numeric string without leading zeros)' });
      return;
    }

    if (slippage === undefined) {
      res.status(400).json({ error: 'Missing slippage' });
      return;
    }

    let parsedSlippage: number;
    try {
      parsedSlippage = parseSlippage(slippage);
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Invalid slippage' });
      return;
    }

    // Determine collateral asset
    if (!collateral_asset) {
      res.status(400).json({ error: 'Missing collateral_asset in request' });
      return;
    }

    if (!isAddress(collateral_asset)) {
      res.status(400).json({ error: 'Invalid collateral_asset address' });
      return;
    }

    // Determine mint adapter / beneficiary address
    let finalAdapterAddress: Hex;
    if (adapter_address) {
      if (!isAddress(adapter_address)) {
        res.status(400).json({ error: 'Invalid adapter_address provided' });
        return;
      }
      finalAdapterAddress = adapter_address as Hex;
    } else {
      if (!isAddress(config.aegis.beneficiary)) {
        res.status(500).json({ error: 'Mint adapter address not configured correctly (AEGIS_BENEFICIARY)' });
        return;
      }
      finalAdapterAddress = config.aegis.beneficiary as Hex;
    }

    // 2. Construct Message and Sign
    // Signing collateral_asset + amount as per original logic requirements
    const textToSign = `${collateral_asset}${collateral_amount}`;
    const signature = await signMessage(textToSign);

    // 3. Call Aegis API
    const payload = {
      address: getSignerAddress(),
      beneficiary_address: finalAdapterAddress,
      collateral_asset: collateral_asset,
      collateral_amount,
      signature,
      slippage: parsedSlippage,
      token_address: config.aegis.tokenAddress
    };

    if (config.debug) {
      console.log('Sending payload to Aegis:', payload);
    } else {
      console.log(`[Mint] asset=${collateral_asset} amount=${collateral_amount} slippage=${parsedSlippage} adapter=${finalAdapterAddress}`);
    }

    const aegisResponse = await fetch(config.aegis.apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': config.aegis.apiKey
      },
      body: JSON.stringify(payload)
    });

    if (!aegisResponse.ok) {
      const errorText = await aegisResponse.text();
      console.error('Aegis API error:', aegisResponse.status, errorText);
      res.status(aegisResponse.status).json({ error: `Aegis API failed: ${errorText}` });
      return;
    }

    const responseData = await aegisResponse.json() as any;

    // 4. Process Response
    if (responseData.status === 'success' && responseData.data) {
      const { order, signature: responseSignature } = responseData.data;
      const { yusd_amount, slippage_adjusted_amount, expiry, nonce, additional_data } = order;

      // Check timestamps from Aegis API response
      const currentTime = Math.floor(Date.now() / 1000); // Current Unix timestamp in seconds
      const timestamps: Record<string, number> = {};

      // Find all timestamp-like fields in the response
      const findTimestamps = (obj: any, prefix = ''): void => {
        if (obj === null || obj === undefined) return;
        if (typeof obj === 'object') {
          for (const [key, value] of Object.entries(obj)) {
            const fullKey = prefix ? `${prefix}.${key}` : key;
            if (typeof value === 'number' && value > 1000000000 && value < 9999999999) {
              // Likely a Unix timestamp (between 2001 and 2286)
              timestamps[fullKey] = value;
            } else if (typeof value === 'string' && /^\d{10}$/.test(value)) {
              // String timestamp
              const ts = parseInt(value, 10);
              if (ts > 1000000000 && ts < 9999999999) {
                timestamps[fullKey] = ts;
              }
            } else if (typeof value === 'object') {
              findTimestamps(value, fullKey);
            }
          }
        }
      };

      findTimestamps(responseData);

      // Log timestamp differences
      console.log('\n--- Timestamp Analysis ---');
      console.log(`Current time: ${currentTime} (${new Date(currentTime * 1000).toISOString()})`);
      for (const [key, ts] of Object.entries(timestamps)) {
        const diff = ts - currentTime;
        const diffAbs = Math.abs(diff);
        const diffMinutes = Math.floor(diffAbs / 60);
        const diffSeconds = diffAbs % 60;
        const sign = diff >= 0 ? '+' : '-';
        console.log(`${key}: ${ts} (${new Date(ts * 1000).toISOString()}) - ${sign}${diffMinutes}m ${diffSeconds}s from now`);
      }
      console.log('---------------------------\n');

      // Print required fields to console
      if (config.debug) {
        console.log('--- Aegis Response Data ---');
        console.log(JSON.stringify(responseData, null, 2));
        console.log('---------------------------');
      }

      // Encode data for smart contract
      const encodedData = encodeAbiParameters(
        parseAbiParameters('uint256, uint256, uint256, uint256, bytes, bytes'),
        [
          BigInt(yusd_amount),
          BigInt(slippage_adjusted_amount),
          BigInt(expiry),
          BigInt(nonce),
          additional_data as Hex,
          responseSignature as Hex
        ]
      );

      res.json({
        ...responseData,
        encodedData,
        signerSignature: signature
      });
    } else {
      console.warn('Unexpected Aegis response format:', responseData);
      res.json(responseData);
    }

  } catch (error) {
    next(error);
  }
});

// Redeem endpoint
app.post('/redeem', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { yusd_amount, slippage, collateral_asset, adapter_address, instance_address, instance_index } = req.body as Partial<RedeemRequest>;

    // 1. Strict Input Validation
    if (!yusd_amount || typeof yusd_amount !== 'string' || !/^[1-9]\d*$/.test(yusd_amount)) {
      res.status(400).json({ error: 'Invalid yusd_amount (must be a positive numeric string without leading zeros)' });
      return;
    }

    if (slippage === undefined) {
      res.status(400).json({ error: 'Missing slippage' });
      return;
    }

    let parsedSlippage: number;
    try {
      parsedSlippage = parseSlippage(slippage);
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Invalid slippage' });
      return;
    }

    // Determine collateral asset
    if (!collateral_asset) {
      res.status(400).json({ error: 'Missing collateral_asset in request' });
      return;
    }

    if (!isAddress(collateral_asset)) {
      res.status(400).json({ error: 'Invalid collateral_asset address' });
      return;
    }

    // 2. Determine Instance Address and Index
    // If all override parameters are provided, use them directly.
    // Otherwise, fetch from the blockchain using the configured adapter.
    let finalInstanceAddress: Hex;
    let finalInstanceIndex: bigint;

    if (adapter_address && instance_address && instance_index) {
      if (!isAddress(adapter_address)) {
        res.status(400).json({ error: 'Invalid adapter_address provided' });
        return;
      }
      if (!isAddress(instance_address)) {
        res.status(400).json({ error: 'Invalid instance_address provided' });
        return;
      }

      finalInstanceAddress = instance_address as Hex;
      try {
        finalInstanceIndex = BigInt(instance_index);
      } catch {
        res.status(400).json({ error: 'Invalid instance_index provided' });
        return;
      }

      if (config.debug) {
        console.log(`[Redeem] Using manual override: instance=${finalInstanceAddress}, index=${finalInstanceIndex}`);
      }

    } else {
      // Fetch Instance and Index from Adapter via Blockchain
      const adapterAddress = config.aegis.adapterAddress;
      if (!adapterAddress || !isAddress(adapterAddress)) {
        res.status(500).json({ error: 'Adapter address not configured correctly' });
        return;
      }

      try {
        const result = await publicClient.readContract({
          address: adapterAddress as Hex,
          abi: parseAbi(['function getNextAvailableInstance() external view returns (address, uint256)']),
          functionName: 'getNextAvailableInstance',
        });
        finalInstanceAddress = result[0] as Hex;
        finalInstanceIndex = result[1];
      } catch (error: any) {
        console.error('[Contract Error] Failed to fetch instance from adapter:', {
          adapterAddress,
          error: error.message,
          stack: error.stack,
          details: error
        });
        res.status(500).json({ error: `Failed to fetch instance: ${error.message}` });
        return;
      }
    }

    // 3. Construct Message and Sign
    // Signing collateral_asset + yusd_amount
    const textToSign = `${collateral_asset}${yusd_amount}`;
    const signature = await signMessage(textToSign);

    // 4. Call Aegis API
    const payload = {
      address: getSignerAddress(),
      beneficiary_address: finalInstanceAddress,
      collateral_asset: collateral_asset,
      yusd_amount,
      signature,
      slippage: parsedSlippage
    };

    if (config.debug) {
      console.log('Sending payload to Aegis (Redeem):', payload);
    } else {
      console.log(`[Redeem] asset=${collateral_asset} amount=${yusd_amount} slippage=${parsedSlippage}`);
    }

    const aegisResponse = await fetch(config.aegis.redeemUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': config.aegis.apiKey
      },
      body: JSON.stringify(payload)
    });

    if (!aegisResponse.ok) {
      const errorText = await aegisResponse.text();
      console.error('Aegis API error (Redeem):', aegisResponse.status, errorText);
      res.status(aegisResponse.status).json({ error: `Aegis API failed: ${errorText}` });
      return;
    }

    const responseData = await aegisResponse.json() as any;

    // 4. Process Response
    if (responseData.status === 'success' && responseData.data) {
      const { order, signature: responseSignature } = responseData.data;
      const { yusd_amount, collateral_amount, slippage_adjusted_amount, expiry, nonce, additional_data } = order;

      // Print required fields to console
      if (config.debug) {
        console.log('--- Aegis Response Data (Redeem) ---');
        console.log(JSON.stringify(responseData, null, 2));
        console.log('---------------------------');
      }

      // Encode data for smart contract
      const encodedData = encodeAbiParameters(
        parseAbiParameters('uint256, uint256, uint256, uint256, uint256, uint256, bytes, bytes'),
        [
          BigInt(finalInstanceIndex),
          BigInt(yusd_amount),
          BigInt(collateral_amount),
          BigInt(slippage_adjusted_amount),
          BigInt(expiry),
          BigInt(nonce),
          additional_data as Hex,
          responseSignature as Hex
        ]
      );

      res.json({
        ...responseData,
        encodedData,
        signerSignature: signature
      });
    } else {
      console.warn('Unexpected Aegis response format (Redeem):', responseData);
      res.json(responseData);
    }

  } catch (error) {
    next(error);
  }
});

// Centralized Error Handling
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[Error]', err.message);

  // Check if headers have already been sent to avoid "Cannot set headers after they are sent to the client"
  if (res.headersSent) {
    return _next(err);
  }

  res.status(500).json({
    error: 'Internal Server Error',
  });
});

// Start Server
app.listen(config.port, '127.0.0.1', () => {
  console.log(`🚀 Server running on port ${config.port} (bound to 127.0.0.1)`);
  console.log(`📝 Signer address: ${getSignerAddress()}`);
});
