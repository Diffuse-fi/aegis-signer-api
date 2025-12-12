# Aegis Signer API

A secure Express.js service for interacting with the Aegis protocol. It acts as an intermediary to sign requests with a configured private key and forward them to the Aegis API.

## Features

- **Endpoints**: `/mint` and `/redeem` for Aegis protocol interactions.
- **Security**: Implements `helmet` for security headers and `express-rate-limit` for DDoS protection.
- **Documentation**: Swagger UI available at `/api-docs`.
- **Validation**: Strict input validation using `viem`.
- **Smart Contract Integration**: Reads from the Aegis Adapter contract for redeem logic.

## Setup

1.  **Install Dependencies**
    ```bash
    npm install
    ```

2.  **Configure Environment**
    Copy the example environment file and configure your variables.
    ```bash
    cp env.example .env
    ```
    Required variables:
    - `ETH_PRIVATE_KEY`: Private key for the signer wallet.
    - `ETH_RPC_URL`: Ethereum RPC URL (required for reading contract state in `/redeem`).
    - `AEGIS_API_KEY`: API key for the Aegis backend.
    - `AEGIS_*`: Various Aegis protocol contract addresses and URLs.

3.  **Build**
    ```bash
    npm run build
    ```

## Development

1.  **Start the Server**
    ```bash
    npm run dev
    ```
    The server runs on `http://127.0.0.1:3000` by default.

2.  **Swagger Documentation**
    Visit `http://127.0.0.1:3000/api-docs` to view the interactive API documentation.

3.  **Manual Testing**
    You can run the included test scripts to verify functionality:
    ```bash
    # Test Mint Flow
    npm run test:manual
    
    # Test Redeem Flow
    npx tsx scripts/test-redeem.ts
    ```

## API Endpoints

### `POST /mint`

Signs a request to mint tokens and forwards it to the Aegis API.

**Request Body:**
```json
{
  "collateral_amount": "1000000",
  "slippage": 1,
  "collateral_asset": "0xdAC17F958D2ee523a2206206994597C13D831ec7"
}
```

### `POST /redeem`

Signs a request to redeem tokens. It fetches the next available instance index from the Aegis Adapter contract (via RPC) unless overrides are provided.

**Request Body:**
```json
{
  "yusd_amount": "2000000000000000000",
  "slippage": 1,
  "collateral_asset": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "adapter_address": "0x...", // Optional override
  "instance_address": "0x...", // Optional override
  "instance_index": "0"        // Optional override
}
```

### `GET /health`

Returns server health status and the configured signer address.

**Response:**
```json
{
  "status": "ok",
  "signer": "0x..."
}
```

## Security

- **CORS**: Configurable via `CORS_ORIGIN` env var (comma-separated list of allowed origins).
- **Rate Limiting**: Limits requests per IP (default: 100 requests per 15 minutes).
- **Trust Proxy**: Configured to trust the first proxy (useful for Nginx setups).
- **Error Handling**: Internal errors are masked in production responses.
