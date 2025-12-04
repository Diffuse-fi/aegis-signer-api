export enum OrderType {
  MINT = 0,
  REDEEM = 1,
  DEPOSIT_INCOME = 2
}

export interface Order {
  orderType: OrderType;
  userWallet: `0x${string}`;
  collateralAsset: `0x${string}`;
  collateralAmount: bigint;
  yusdAmount: bigint;
  slippageAdjustedAmount: bigint;
  expiry: bigint;
  nonce: bigint;
  additionalData: `0x${string}`;
}

