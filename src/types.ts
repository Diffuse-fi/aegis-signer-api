export interface SignRequest {
  collateral_amount: string;
  slippage: number;
  collateral_asset: string;
  /**
   * Optional mint adapter override (beneficiary_address sent to Aegis).
   * If omitted, server uses AEGIS_BENEFICIARY from env.
   */
  adapter_address?: string;
}

export interface RedeemRequest {
  yusd_amount: string;
  slippage: number;
  collateral_asset: string;
  adapter_address?: string;
  instance_address?: string;
  instance_index?: string; // string to safely handle large numbers/BigInt via JSON
}
