import express, { type Request, type Response } from 'express';
import cors from 'cors';
import morgan from 'morgan';
import dotenv from 'dotenv';
import { signOrder, getSignerAddress } from './signer.js';
import { type Order, OrderType } from './types.js';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(morgan('combined'));
app.use(express.json());

app.get('/ping', (req: Request, res: Response) => {
  res.send('pong');
});

// Helper to safely parse BigInt from string
const toBigInt = (val: any): bigint => {
  try {
    return BigInt(val);
  } catch (e) {
    throw new Error(`Invalid BigInt value: ${val}`);
  }
};

app.post('/sign', async (req: Request, res: Response): Promise<void> => {
  try {
    const orderData = req.body;

    if (!orderData) {
      res.status(400).json({ error: 'Missing order data' });
      return;
    }

    // Explicitly construct order to ensure types
    const order: Order = {
      orderType: orderData.orderType as OrderType,
      userWallet: orderData.userWallet,
      collateralAsset: orderData.collateralAsset,
      collateralAmount: toBigInt(orderData.collateralAmount),
      yusdAmount: toBigInt(orderData.yusdAmount),
      slippageAdjustedAmount: toBigInt(orderData.slippageAdjustedAmount),
      expiry: toBigInt(orderData.expiry),
      nonce: toBigInt(orderData.nonce),
      additionalData: orderData.additionalData
    };

    const signature = await signOrder(order);
    const signer = getSignerAddress();

    // Serialize BigInts to strings for JSON response
    res.json({
      signature,
      signer,
      order: {
        ...order,
        collateralAmount: order.collateralAmount.toString(),
        yusdAmount: order.yusdAmount.toString(),
        slippageAdjustedAmount: order.slippageAdjustedAmount.toString(),
        expiry: order.expiry.toString(),
        nonce: order.nonce.toString()
      }
    });
  } catch (error) {
    console.error('Signing error:', error);
    res.status(500).json({ error: 'Failed to sign order', details: (error as Error).message });
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

