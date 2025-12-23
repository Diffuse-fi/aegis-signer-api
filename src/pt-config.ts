import dotenv from 'dotenv';
import { isAddress, type Address } from 'viem';

dotenv.config();

const getEnvVar = (key: string, required = true): string => {
  const value = process.env[key];
  if (required && !value) {
    throw new Error(`Environment variable ${key} is required`);
  }
  return value || '';
};

const getCorsOrigin = (raw: string): string | string[] => {
  const origins = raw
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);

  if (origins.length === 0) return '*';
  if (origins.includes('*')) return '*';
  return origins;
};

const getAddressEnv = (key: string, fallback?: Address): Address => {
  const raw = getEnvVar(key, !fallback);
  const value = (raw || fallback || '') as Address;
  if (!isAddress(value)) {
    throw new Error(`Environment variable ${key} must be a valid address`);
  }
  return value;
};

const alchemyApiKey = getEnvVar('ALCHEMY_API_KEY');

export const ptConfig = {
  port: parseInt(getEnvVar('PT_API_PORT', false), 10) || 3100,
  corsOrigin: getCorsOrigin(getEnvVar('PT_CORS_ORIGIN', false)),
  debug: getEnvVar('DEBUG', false) === 'true',
  alchemy: {
    apiKey: alchemyApiKey,
    rpcUrl: `https://eth-mainnet.g.alchemy.com/v2/${alchemyApiKey}`,
  },
  usdcHolder: getAddressEnv('USDC_HOLDER', '0x37305B1cD40574E4C5Ce33f8e8306Be057fD7341'),
  // Pendle viewer / simulator contract (can be changed without code edits)
  viewerAddress: getAddressEnv('PT_VIEWER_ADDRESS', '0x2B29dEa1231AA37929d11Aa176D6643181482B22'),
} as const;


