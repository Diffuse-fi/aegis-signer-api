import express, { type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import morgan from 'morgan';
import { isAddress } from 'viem';
import { signMessage, getSignerAddress } from './signer.js';
import { type SignRequest } from './types.js';
import { config } from './config.js';

const app = express();

// Security: Disable 'x-powered-by' header to reduce fingerprinting
app.disable('x-powered-by');

// Security headers
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Middleware
app.use(cors({
  origin: config.corsOrigin,
  credentials: false,
}));
app.use(morgan('dev'));
app.use(express.json({ limit: '10kb' })); // Limit body size to prevent DoS

// Health check
app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({ status: 'ok', signer: getSignerAddress() });
});

// Sign endpoint
app.post('/sign', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const { address, amount } = req.body as Partial<SignRequest>;

    // 1. Strict Input Validation
    if (!address || !isAddress(address)) {
      res.status(400).json({ error: 'Invalid or missing Ethereum address' });
      return;
    }

    if (!amount || typeof amount !== 'string' || !/^[1-9]\d*$/.test(amount)) {
      res.status(400).json({ error: 'Invalid amount (must be a positive numeric string without leading zeros)' });
      return;
    }

    // 2. Construct Message
    // Note: Concatenation without separator can be ambiguous. Ensure this matches spec.
    const textToSign = `${address}${amount}`;

    // 3. Sign
    const signature = await signMessage(textToSign);

    res.json({
      signature,
      signer: getSignerAddress(),
      signedText: textToSign
    });
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
app.listen(config.port, () => {
  console.log(`🚀 Server running on port ${config.port}`);
  console.log(`📝 Signer address: ${getSignerAddress()}`);
});
