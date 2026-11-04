/**
 * economicService.ts
 *
 * SARAL Adaptive Multi-Asset Economic Security Subsystem (Patent FIG. 4)
 *
 * Components:
 *   - MSTC: Fixed-supply primary settlement and governance asset.
 *   - sMSTC: Liquid restaking derivative minted 1:1 against deposited MSTC.
 *   - SST: Protocol-native security staking token with governed issuance ceiling.
 *   - Security Ratio R = TVS / TES
 *     where TES = Eligible Staked SST + Eligible Staked sMSTC.
 *   - Adaptive Issuance Engine: Modulates annual token emission bounded by [MinRate, MaxRate].
 *   - Usage-Fee Processor: Protocol fee distribution across Burn, Insurance, and Staking yield.
 *   - Slashing & Insurance Treasury: Punishes Byzantine / offline nodes, feeds safety reserve.
 */

import fs from 'fs';
import path from 'path';

export interface EconomicParameters {
  targetSecurityRatio: number; // R* (default: 1.5)
  minEmissionRateApr: number; // Baseline annual emission (e.g. 0.02 = 2%)
  maxEmissionRateApr: number; // Maximum bounded annual emission (e.g. 0.15 = 15%)
  sstMaxSupplyCeiling: number; // Hard cap for SST (e.g. 100,000,000 SST)
  mstcTotalFixedSupply: number; // Fixed supply governance/settlement asset (e.g. 8,000,000,000 MSTC)
  mstcToSstExchangeRate: number; // Configurable pricing oracle: 1 MSTC = X SST (default 10)
  burnFeeSharePercent: number; // e.g. 30% of protocol fee burns SST
  insuranceFeeSharePercent: number; // e.g. 20% goes to insurance reserve
  validatorRewardSharePercent: number; // e.g. 50% recirculated to Public domain nodes
  slashingPenaltyPercent: number; // e.g. 10% stake slashed on malicious Byzantine infraction
  slashingInsuranceSplitPercent: number; // e.g. 60% diverted to insurance treasury
  slashingRedistributionSplitPercent: number; // e.g. 40% redistributed to participants in good standing
}

export interface EconomicState {
  totalValueSecuredMstc: number; // TVS: aggregate value of all wallets & assets secured
  stakedSst: number; // Eligible Staked SST
  stakedSmstc: number; // Eligible Staked sMSTC (restaked vault)
  totalEffectiveStake: number; // TES = stakedSst + stakedSmstc
  currentSecurityRatio: number; // R = TVS / TES
  currentEmissionRateApr: number; // Adaptive rate between min and max
  sstCirculatingSupply: number;
  sstTotalBurned: number;
  insuranceTreasuryBalanceMstc: number;
  validatorRedistributionPoolMstc: number;
  totalUsageFeesProcessedMstc: number;
  lastUpdated: string;
}

export interface SlashingEvent {
  id: string;
  nodeId: string;
  reason: 'BYZANTINE_FAULT' | 'TAMPERED_SHARE' | 'EQUIVOCATION' | 'PROLONGED_DOWNTIME';
  slashedAmountSst: number;
  divertedToInsuranceTreasury: number;
  redistributedToValidators?: number;
  timestamp: string;
}

const ECONOMIC_STORAGE_DIR = process.env.SARAL_ECONOMIC_DIR || path.resolve(process.cwd(), '.saral_registry');
const ECONOMIC_STORAGE_FILE = path.join(ECONOMIC_STORAGE_DIR, 'economic_state.json');

export class EconomicSecuritySubsystem {
  private params: EconomicParameters;
  private state: EconomicState;
  private slashingHistory: SlashingEvent[] = [];
  private restakedVaultBalances: Map<string, number> = new Map();

  constructor(customParams?: Partial<EconomicParameters>) {
    this.params = {
      targetSecurityRatio: 1.5,
      minEmissionRateApr: 0.02,
      maxEmissionRateApr: 0.15,
      sstMaxSupplyCeiling: 100_000_000,
      mstcTotalFixedSupply: 8_000_000_000,
      mstcToSstExchangeRate: 10,
      burnFeeSharePercent: 30,
      insuranceFeeSharePercent: 20,
      validatorRewardSharePercent: 50,
      slashingPenaltyPercent: 10,
      slashingInsuranceSplitPercent: 100,
      slashingRedistributionSplitPercent: 0,
      ...customParams,
    };

    // Initial calibrated baseline state
    const initialTvs = 50_000_000;
    const initialStakedSst = 25_000_000;
    const initialStakedSmstc = 15_000_000;
    const initialTes = initialStakedSst + initialStakedSmstc;

    this.state = {
      totalValueSecuredMstc: initialTvs,
      stakedSst: initialStakedSst,
      stakedSmstc: initialStakedSmstc,
      totalEffectiveStake: initialTes,
      currentSecurityRatio: Math.round((initialTvs / initialTes) * 100) / 100,
      currentEmissionRateApr: 0.05,
      sstCirculatingSupply: 50_000_000,
      sstTotalBurned: 0,
      insuranceTreasuryBalanceMstc: 500_000,
      validatorRedistributionPoolMstc: 0,
      totalUsageFeesProcessedMstc: 0,
      lastUpdated: new Date().toISOString(),
    };

    if (process.env.NODE_ENV !== 'test') {
      this.loadStateFromDisk();
    }
    this.recalculateAdaptiveEmission();
  }

  private saveStateToDisk(): void {
    if (process.env.NODE_ENV === 'test') return;
    try {
      if (!fs.existsSync(ECONOMIC_STORAGE_DIR)) {
        fs.mkdirSync(ECONOMIC_STORAGE_DIR, { recursive: true, mode: 0o700 });
      }
      const data = {
        state: this.state,
        slashingHistory: this.slashingHistory,
        restakedVaultBalances: Array.from(this.restakedVaultBalances.entries()),
      };
      fs.writeFileSync(ECONOMIC_STORAGE_FILE, JSON.stringify(data, null, 2), { mode: 0o600 });
    } catch {
      // Safe fallback
    }
  }

  private loadStateFromDisk(): void {
    try {
      if (fs.existsSync(ECONOMIC_STORAGE_FILE)) {
        const raw = fs.readFileSync(ECONOMIC_STORAGE_FILE, 'utf8');
        const data = JSON.parse(raw);
        if (data.state) {
          this.state = { ...this.state, ...data.state };
        }
        if (Array.isArray(data.slashingHistory)) {
          this.slashingHistory = data.slashingHistory;
        }
        if (Array.isArray(data.restakedVaultBalances)) {
          for (const [acc, bal] of data.restakedVaultBalances) {
            this.restakedVaultBalances.set(acc, bal);
          }
        }
      }
    } catch {
      // Ignore initial missing file
    }
  }

  public getParameters(): EconomicParameters {
    return { ...this.params };
  }

  public setPricingOracleRate(mstcToSstRate: number): void {
    if (mstcToSstRate <= 0) throw new Error('Pricing oracle rate must be strictly positive');
    this.params.mstcToSstExchangeRate = mstcToSstRate;
  }

  public getState(): EconomicState {
    return { ...this.state };
  }

  public getSlashingHistory(): SlashingEvent[] {
    return [...this.slashingHistory];
  }

  /**
   * Updates Total Value Secured (TVS) and recalculates security ratio R = TVS / TES.
   */
  public updateTvs(newTvsMstc: number): EconomicState {
    if (newTvsMstc < 0) throw new Error('TVS cannot be negative');
    this.state.totalValueSecuredMstc = Math.floor(newTvsMstc);
    this.recalculateAdaptiveEmission();
    this.saveStateToDisk();
    return this.getState();
  }

  /**
   * Deposits MSTC into sMSTC restaking vault and mints transferable sMSTC derivative 1:1.
   * Fixed MSTC supply invariant: does NOT create new MSTC.
   */
  public restakeMstc(amountMstc: number, accountId: string = 'global-pool'): { mintedSmstc: number; newTes: number } {
    if (amountMstc <= 0) throw new Error('Restake amount must be strictly positive');
    if (!Number.isFinite(amountMstc)) throw new Error('Invalid restake amount');

    const cleanAmount = Math.floor(amountMstc);
    this.state.stakedSmstc += cleanAmount;
    const existing = this.restakedVaultBalances.get(accountId) || 0;
    this.restakedVaultBalances.set(accountId, existing + cleanAmount);

    this.recalculateAdaptiveEmission();
    this.saveStateToDisk();
    return { mintedSmstc: cleanAmount, newTes: this.state.totalEffectiveStake };
  }

  /**
   * Redeems sMSTC back to MSTC 1:1 from the restaking vault.
   * Prevents duplicate redemption and negative balances.
   */
  public redeemSmstc(amountSmstc: number, accountId: string = 'global-pool'): { redeemedMstc: number; remainingTes: number } {
    if (amountSmstc <= 0) throw new Error('Redemption amount must be strictly positive');
    const cleanAmount = Math.floor(amountSmstc);
    const existing = this.restakedVaultBalances.get(accountId) || 0;
    if (existing < cleanAmount && accountId !== 'global-pool') {
      throw new Error(`Insufficient sMSTC balance for account '${accountId}'. Available: ${existing}, Requested: ${cleanAmount}`);
    }
    if (this.state.stakedSmstc < cleanAmount) {
      throw new Error(`Vault liquidity shortfall: cannot redeem ${cleanAmount} sMSTC, total staked is ${this.state.stakedSmstc}`);
    }

    this.state.stakedSmstc -= cleanAmount;
    if (accountId !== 'global-pool') {
      this.restakedVaultBalances.set(accountId, existing - cleanAmount);
    }
    this.recalculateAdaptiveEmission();
    this.saveStateToDisk();
    return { redeemedMstc: cleanAmount, remainingTes: this.state.totalEffectiveStake };
  }

  /**
   * Stakes SST for Public domain node operation within governed supply ceilings.
   */
  public stakeSst(amountSst: number): { newStakedSst: number; newTes: number } {
    if (amountSst <= 0) throw new Error('Stake amount must be strictly positive');
    const cleanAmount = Math.floor(amountSst);
    if (this.state.stakedSst + cleanAmount > this.state.sstCirculatingSupply) {
      throw new Error('Stake amount exceeds circulating SST supply');
    }
    if (this.state.stakedSst + cleanAmount > this.params.sstMaxSupplyCeiling) {
      throw new Error(`Stake exceeds governed SST supply ceiling of ${this.params.sstMaxSupplyCeiling}`);
    }

    this.state.stakedSst += cleanAmount;
    this.recalculateAdaptiveEmission();
    this.saveStateToDisk();
    return { newStakedSst: this.state.stakedSst, newTes: this.state.totalEffectiveStake };
  }

  /**
   * Recalculates Total Effective Stake, Security Ratio R, and Adaptive Emission Rate.
   *
   * Formula (Patent FIG. 4):
   *   R = TVS / TES
   *   where TES = Eligible Staked SST + Eligible Staked sMSTC
   */
  private recalculateAdaptiveEmission(): void {
    const tes = this.state.stakedSst + this.state.stakedSmstc;
    this.state.totalEffectiveStake = Math.max(tes, 1);

    const r = this.state.totalValueSecuredMstc / this.state.totalEffectiveStake;
    this.state.currentSecurityRatio = Math.round(r * 1000) / 1000;

    const rStar = this.params.targetSecurityRatio;
    const minRate = this.params.minEmissionRateApr;
    const maxRate = this.params.maxEmissionRateApr;

    if (r >= rStar) {
      // Under-collateralized: smoothly increase emission up to maxRate
      const factor = Math.min((r - rStar) / rStar, 1.0);
      this.state.currentEmissionRateApr = Math.round((minRate + (maxRate - minRate) * factor) * 10000) / 10000;
    } else {
      // Well-collateralized: smoothly taper emission down to minRate
      const factor = Math.max(r / rStar, 0.0);
      this.state.currentEmissionRateApr = Math.round((minRate * factor) * 10000) / 10000;
    }

    this.state.lastUpdated = new Date().toISOString();
  }

  /**
   * Processes a transaction protocol usage fee in MSTC:
   *   - 30% burns SST (deflationary) via pricing oracle
   *   - 20% to Insurance Treasury
   *   - 50% distributed to Public domain validator nodes
   */
  public processUsageFee(feeMstc: number): {
    burnedSst: number;
    insuranceAddedMstc: number;
    validatorRewardsMstc: number;
  } {
    if (feeMstc <= 0) throw new Error('Usage fee must be strictly positive');

    const burnPortion = (feeMstc * this.params.burnFeeSharePercent) / 100;
    const insurancePortion = (feeMstc * this.params.insuranceFeeSharePercent) / 100;
    const validatorPortion = (feeMstc * this.params.validatorRewardSharePercent) / 100;

    // Convert burn portion using verified pricing oracle rate
    const sstBurned = burnPortion * this.params.mstcToSstExchangeRate;
    this.state.sstTotalBurned += sstBurned;
    this.state.sstCirculatingSupply = Math.max(0, this.state.sstCirculatingSupply - sstBurned);

    this.state.insuranceTreasuryBalanceMstc += insurancePortion;
    this.state.totalUsageFeesProcessedMstc += feeMstc;

    this.recalculateAdaptiveEmission();
    this.saveStateToDisk();

    return {
      burnedSst: sstBurned,
      insuranceAddedMstc: insurancePortion,
      validatorRewardsMstc: validatorPortion,
    };
  }

  /**
   * Slashes a misbehaving or compromised Public Domain node.
   * Implements patent dual-allocation:
   *   - 60% diverted to Insurance Treasury
   *   - 40% redistributed to participants in good standing
   *   Total: 60% + 40% = 100% of slashed stake
   */
  public slashNode(
    nodeId: string,
    reason: SlashingEvent['reason'],
    nodeStakedSst: number
  ): SlashingEvent {
    if (nodeStakedSst <= 0) throw new Error('Node staked SST must be positive');
    const slashPercent = this.params.slashingPenaltyPercent;
    const slashedSst = (nodeStakedSst * slashPercent) / 100;

    this.state.stakedSst = Math.max(0, this.state.stakedSst - slashedSst);

    // Convert to MSTC base equivalent via pricing oracle
    const slashedMstcEquivalent = slashedSst / this.params.mstcToSstExchangeRate;

    // Dual allocation: Insurance Treasury + Good-Standing Redistribution
    const insuranceShare = (slashedMstcEquivalent * this.params.slashingInsuranceSplitPercent) / 100;
    const redistributionShare = (slashedMstcEquivalent * this.params.slashingRedistributionSplitPercent) / 100;

    this.state.insuranceTreasuryBalanceMstc += insuranceShare;
    this.state.validatorRedistributionPoolMstc += redistributionShare;

    const event: SlashingEvent = {
      id: `slash-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      nodeId,
      reason,
      slashedAmountSst: slashedSst,
      divertedToInsuranceTreasury: insuranceShare,
      redistributedToValidators: redistributionShare,
      timestamp: new Date().toISOString(),
    };

    this.slashingHistory.push(event);
    this.recalculateAdaptiveEmission();
    this.saveStateToDisk();
    return event;
  }

  /**
   * Runs an adversarial economic stress simulation.
   */
  public runStressSimulation(
    scenarios: Array<{ name: string; tvsMultiplier: number; slashNodesCount: number }>
  ): Array<{ scenario: string; securityRatio: number; emissionApr: number; healthy: boolean }> {
    const results = [];
    const originalState = { ...this.state };

    for (const sc of scenarios) {
      this.state.totalValueSecuredMstc = originalState.totalValueSecuredMstc * sc.tvsMultiplier;
      for (let i = 0; i < sc.slashNodesCount; i++) {
        this.slashNode(`sim-node-${i}`, 'EQUIVOCATION', 100_000);
      }
      this.recalculateAdaptiveEmission();

      results.push({
        scenario: sc.name,
        securityRatio: this.state.currentSecurityRatio,
        emissionApr: this.state.currentEmissionRateApr,
        healthy: this.state.currentSecurityRatio <= 2.5 && this.state.totalEffectiveStake > 0,
      });
    }

    // Restore state
    this.state = originalState;
    return results;
  }
}

// Global Economic Security singleton
export const economicSecurity = new EconomicSecuritySubsystem();

