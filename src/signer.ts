import { createWalletClient, http, type Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { mainnet } from 'viem/chains';
import dotenv from 'dotenv';

dotenv.config();

const privateKey = process.env.ETH_PRIVATE_KEY as Hex;
if (!privateKey) {
  console.warn('ETH_PRIVATE_KEY is not set in environment variables');
}

const account = privateKey ? privateKeyToAccount(privateKey) : undefined;

const client = createWalletClient({
  account,
  chain: mainnet,
  transport: http()
});

export async function signMessage(textToSign: string) {
  if (!account) {
    throw new Error('Signer account not initialized (check ETH_PRIVATE_KEY)');
  }

  // The example uses simple personal_sign with hex encoded string
  // In viem, signMessage automatically handles the prefixing
  // "0x" + hex(text) is what we want to sign

  // Convert text to hex string if it's not already
  const signature = await client.signMessage({
    account,
    message: textToSign,
  });

  return signature;
}

export function getSignerAddress() {
  return account?.address;
}
