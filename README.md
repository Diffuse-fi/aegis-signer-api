# Aegis Signer API

A simple Express.js service that signs concatenated address and amount strings using an Ethereum private key via `personal_sign`.

## Setup

1.  **Install Dependencies**
    ```bash
    npm install
    ```

2.  **Configure Environment**
    Copy the example environment file and set your `ETH_PRIVATE_KEY`.
    ```bash
    cp .env.example .env
    # Edit .env and add your private key
    ```

## Development

1.  **Start the Server**
    ```bash
    npm run dev
    ```
    The server runs on `http://localhost:3000` by default.

2.  **Run Manual Test**
    Open a second terminal and run:
    ```bash
    npm run test:manual
    ```

## API Endpoints

### `POST /sign`

Accepts an address and amount, concatenates them, and returns the signature.

**Request Body:**
```json
{
  "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
  "amount": "1000000"
}
```

**Response:**
```json
{
  "signature": "0x...",
  "signer": "0x...",
  "signedText": "0xdAC17F958D2ee523a2206206994597C13D831ec71000000"
}
```

### `GET /ping`

Returns `pong` to check server health.

