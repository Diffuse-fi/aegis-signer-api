import { createWalletClient, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { mainnet } from 'viem/chains';
import { config } from './config.js';

// Initialize account once at startup. Fail fast if invalid.
let account: ReturnType<typeof privateKeyToAccount>;
try {
  account = privateKeyToAccount(config.privateKey);
} catch (error) {
  const message = error instanceof Error ? error.message : 'Unknown error';
  throw new Error(`Failed to initialize account from private key: ${message}`);
}

const client = createWalletClient({
  account,
  chain: mainnet,
  transport: http(),
});

/**
 * Signs a plain text message using the configured account.
 * Note: This produces an EIP-191 signature (0x19 <0x45 (E)> <personal_sign prefix> <length> <data>).
 */
export async function signMessage(textToSign: string): Promise<string> {
  if (!textToSign) {
    throw new Error('Message content cannot be empty');
  }

  return client.signMessage({
    account,
    message: textToSign,
  });
}

export function getSignerAddress() {
  return account.address;
}
