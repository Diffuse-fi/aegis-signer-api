import express, { type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import morgan from 'morgan';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import swaggerUi from 'swagger-ui-express';
import fs from 'fs';
import { isAddress, encodeAbiParameters, parseAbiParameters, type Hex } from 'viem';
import { signMessage, getSignerAddress } from './signer.js';
import { type SignRequest } from './types.js';
import { config } from './config.js';

// Load swagger.json
const swaggerDocument = JSON.parse(fs.readFileSync(new URL('../swagger.json', import.meta.url), 'utf8'));

const app = express();

// Security: Helmet for security headers
app.use(helmet());

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
  max: 100, // Limit each IP to 100 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Health check
app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({ status: 'ok', signer: getSignerAddress() });
});

// Mint endpoint
app.post('/mint', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { collateral_amount, slippage, collateral_asset } = req.body as Partial<SignRequest>;

    // 1. Strict Input Validation
    if (!collateral_amount || typeof collateral_amount !== 'string' || !/^[1-9]\d*$/.test(collateral_amount)) {
      res.status(400).json({ error: 'Invalid collateral_amount (must be a positive numeric string without leading zeros)' });
      return;
    }

    if (slippage === undefined || typeof slippage !== 'number') {
      res.status(400).json({ error: 'Invalid or missing slippage (must be a number)' });
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

    // 2. Construct Message and Sign
    // Signing collateral_asset + amount as per original logic requirements
    const textToSign = `${collateral_asset}${collateral_amount}`;
    const signature = await signMessage(textToSign);

    // 3. Call Aegis API
    const payload = {
      address: getSignerAddress(),
      beneficiary_address: config.aegis.beneficiary,
      collateral_asset: collateral_asset,
      collateral_amount,
      signature,
      slippage,
      token_address: config.aegis.tokenAddress
    };

    if (config.debug) {
      console.log('Sending payload to Aegis:', payload);
    } else {
      console.log(`[Mint] asset=${collateral_asset} amount=${collateral_amount} slippage=${slippage}`);
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

      // Print required fields to console
      if (config.debug) {
        console.log('--- Aegis Response Data ---');
        console.log('yusd_amount:', yusd_amount);
        console.log('slippage_adjusted_amount:', slippage_adjusted_amount);
        console.log('expiry:', expiry);
        console.log('nonce:', nonce);
        console.log('additional_data:', additional_data);
        console.log('signature:', responseSignature);
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

// Centralized Error Handling
app.use((err: Error, _req: Request, res: Response) => {
  console.error('[Error]', err.message);
  res.status(500).json({
    error: 'Internal Server Error',
  });
});

// Start Server
app.listen(config.port, '127.0.0.1', () => {
  console.log(`🚀 Server running on port ${config.port} (bound to 127.0.0.1)`);
  console.log(`📝 Signer address: ${getSignerAddress()}`);
});
