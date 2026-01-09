import dotenv from 'dotenv';
import { type Hex, isHex } from 'viem';

dotenv.config();

const getEnvVar = (key: string, required = true): string => {
  const value = process.env[key];
  if (required && !value) {
    throw new Error(`Environment variable ${key} is required`);
  }
  return value || '';
};

const getPrivateKey = (): Hex => {
  const key = getEnvVar('ETH_PRIVATE_KEY');
  if (!isHex(key) || key.length !== 66) {
    throw new Error('ETH_PRIVATE_KEY must be a valid 66-character hex string (0x + 64 hex chars)');
  }
  return key as Hex;
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

export const config = {
  port: parseInt(getEnvVar('PORT', false), 10) || 3000,
  privateKey: getPrivateKey(),
  corsOrigin: getCorsOrigin(getEnvVar('CORS_ORIGIN', false)),
  debug: getEnvVar('DEBUG', false) === 'true',
  aegis: {
    beneficiary: getEnvVar('AEGIS_BENEFICIARY'),
    tokenAddress: getEnvVar('AEGIS_TOKEN_ADDRESS'),
    apiKey: getEnvVar('AEGIS_API_KEY'),
    apiUrl: getEnvVar('AEGIS_API_URL'),
    redeemUrl: getEnvVar('AEGIS_REDEEM_URL'),
    adapterAddress: getEnvVar('AEGIS_ADAPTER_ADDRESS'),
  },
  ethRpcUrl: getEnvVar('ETH_RPC_URL')
} as const;

