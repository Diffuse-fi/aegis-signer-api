export interface SignRequest {
  collateral_amount: string;
  slippage: number;
  collateral_asset: string;
}

export interface RedeemRequest {
  yusd_amount: string;
  slippage: number;
  collateral_asset: string;
  adapter_address?: string;
  instance_address?: string;
  instance_index?: string; // string to safely handle large numbers/BigInt via JSON
}
