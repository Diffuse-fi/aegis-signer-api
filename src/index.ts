import express, { type Request, type Response } from 'express';
import cors from 'cors';
import morgan from 'morgan';
import dotenv from 'dotenv';
import { signMessage, getSignerAddress } from './signer.js';
import { type SignRequest } from './types.js';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(morgan('combined'));
app.use(express.json());

app.get('/ping', (req: Request, res: Response) => {
  res.send('pong');
});

app.post('/sign', async (req: Request, res: Response): Promise<void> => {
  try {
    const { address, amount } = req.body as SignRequest;

    if (!address || !amount) {
      res.status(400).json({ error: 'Missing address or amount' });
      return;
    }

    // Concatenate address and amount as per requirement
    // Ensure address matches expected case or format if needed, but requirement says "just string - concatenated"
    const textToSign = `${address}${amount}`;

    const signature = await signMessage(textToSign);
    const signer = getSignerAddress();

    res.json({
      signature,
      signer,
      signedText: textToSign
    });
  } catch (error) {
    console.error('Signing error:', error);
    res.status(500).json({ error: 'Failed to sign message', details: (error as Error).message });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  const address = getSignerAddress();
  if (address) {
    console.log(`Signer address: ${address}`);
  } else {
    console.warn('WARNING: Signer address not available (ETH_PRIVATE_KEY missing)');
  }
});
