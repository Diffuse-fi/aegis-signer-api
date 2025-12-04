import { createWalletClient, http, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { mainnet } from 'viem/chains';
import { type Order } from './types.js';
import dotenv from 'dotenv';

dotenv.config();

const privateKey = process.env.ETH_PRIVATE_KEY as Hex;
if (!privateKey) {
  // We'll warn but not crash immediately to allow build, 
  // but this will throw at runtime if not set when used.
  console.warn('ETH_PRIVATE_KEY is not set in environment variables');
}

const account = privateKey ? privateKeyToAccount(privateKey) : undefined;

const client = createWalletClient({
  account,
  chain: mainnet,
  transport: http()
});

// Domain Separator constants
const DOMAIN_NAME = process.env.DOMAIN_NAME || 'Aegis';
const DOMAIN_VERSION = process.env.DOMAIN_VERSION || '1';
const CHAIN_ID = parseInt(process.env.CHAIN_ID || '1');
const VERIFYING_CONTRACT = (process.env.VERIFYING_CONTRACT as Hex) || '0x0000000000000000000000000000000000000000';

const domain = {
  name: DOMAIN_NAME,
  version: DOMAIN_VERSION,
  chainId: CHAIN_ID,
  verifyingContract: VERIFYING_CONTRACT,
} as const;

const types = {
  Order: [
    { name: 'orderType', type: 'uint8' },
    { name: 'userWallet', type: 'address' },
    { name: 'collateralAsset', type: 'address' },
    { name: 'collateralAmount', type: 'uint256' },
    { name: 'yusdAmount', type: 'uint256' },
    { name: 'slippageAdjustedAmount', type: 'uint256' },
    { name: 'expiry', type: 'uint256' },
    { name: 'nonce', type: 'uint256' },
    { name: 'additionalData', type: 'bytes' },
  ],
} as const;

export async function signOrder(order: Order) {
  if (!account) {
    throw new Error('Signer account not initialized (check ETH_PRIVATE_KEY)');
  }

  const signature = await client.signTypedData({
    account,
    domain,
    types,
    primaryType: 'Order',
    message: order,
  });

  return signature;
}

export function getSignerAddress() {
  return account?.address;
}

