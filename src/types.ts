export interface SignRequest {
  collateral_amount: string;
  slippage: number;
  collateral_asset: string;
}

export interface RedeemRequest {
  yusd_amount: string;
  slippage: number;
  collateral_asset: string;
}
