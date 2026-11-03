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

export interface EconomicParameters {
  targetSecurityRatio: number; // R* (default: 1.5)
  minEmissionRateApr: number; // Baseline annual emission (e.g. 0.02 = 2%)
  maxEmissionRateApr: number; // Maximum bounded annual emission (e.g. 0.15 = 15%)
  sstMaxSupplyCeiling: number; // Hard cap for SST (e.g. 100,000,000 SST)
  burnFeeSharePercent: number; // e.g. 30% of protocol fee burns SST
  insuranceFeeSharePercent: number; // e.g. 20% goes to insurance reserve
  validatorRewardSharePercent: number; // e.g. 50% recirculated to Public domain nodes
  slashingPenaltyPercent: number; // e.g. 10% stake slashed on malicious Byzantine infraction
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
  totalUsageFeesProcessedMstc: number;
  lastUpdated: string;
}

export interface SlashingEvent {
  id: string;
  nodeId: string;
  reason: 'BYZANTINE_FAULT' | 'TAMPERED_SHARE' | 'EQUIVOCATION' | 'PROLONGED_DOWNTIME';
  slashedAmountSst: number;
  divertedToInsuranceTreasury: number;
  timestamp: string;
}

export class EconomicSecuritySubsystem {
  private params: EconomicParameters;
  private state: EconomicState;
  private slashingHistory: SlashingEvent[] = [];

  constructor(customParams?: Partial<EconomicParameters>) {
    this.params = {
      targetSecurityRatio: 1.5,
      minEmissionRateApr: 0.02,
      maxEmissionRateApr: 0.15,
      sstMaxSupplyCeiling: 100_000_000,
      burnFeeSharePercent: 30,
      insuranceFeeSharePercent: 20,
      validatorRewardSharePercent: 50,
      slashingPenaltyPercent: 10,
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
      totalUsageFeesProcessedMstc: 0,
      lastUpdated: new Date().toISOString(),
    };

    this.recalculateAdaptiveEmission();
  }

  public getParameters(): EconomicParameters {
    return { ...this.params };
  }

  public getState(): EconomicState {
    return { ...this.state };
  }

  public getSlashingHistory(): SlashingEvent[] {
    return [...this.slashingHistory];
  }

  /**
   * Updates Total Value Secured (TVS) and recalculates security ratio R.
   */
  public updateTvs(newTvsMstc: number): EconomicState {
    if (newTvsMstc < 0) throw new Error('TVS cannot be negative');
    this.state.totalValueSecuredMstc = newTvsMstc;
    this.recalculateAdaptiveEmission();
    return this.getState();
  }

  /**
   * Deposits MSTC into sMSTC restaking vault.
   */
  public restakeMstc(amountMstc: number): { mintedSmstc: number; newTes: number } {
    if (amountMstc <= 0) throw new Error('Restake amount must be positive');
    this.state.stakedSmstc += amountMstc;
    this.recalculateAdaptiveEmission();
    return { mintedSmstc: amountMstc, newTes: this.state.totalEffectiveStake };
  }

  /**
   * Stakes SST for Public domain node operation.
   */
  public stakeSst(amountSst: number): { newStakedSst: number; newTes: number } {
    if (amountSst <= 0) throw new Error('Stake amount must be positive');
    if (this.state.stakedSst + amountSst > this.state.sstCirculatingSupply) {
      throw new Error('Stake amount exceeds circulating SST supply');
    }
    this.state.stakedSst += amountSst;
    this.recalculateAdaptiveEmission();
    return { newStakedSst: this.state.stakedSst, newTes: this.state.totalEffectiveStake };
  }

  /**
   * Recalculates Total Effective Stake, Security Ratio R, and Adaptive Emission Rate.
   *
   * R = TVS / TES
   * If R > R*: System is under-collateralized -> increase emission up to maxEmissionRateApr
   * If R <= R*: System is well-collateralized -> decrease emission towards minEmissionRateApr
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
   *   - 30% burns SST (deflationary)
   *   - 20% to Insurance Treasury
   *   - 50% distributed to Public domain validator nodes
   */
  public processUsageFee(feeMstc: number): {
    burnedSst: number;
    insuranceAddedMstc: number;
    validatorRewardsMstc: number;
  } {
    if (feeMstc <= 0) throw new Error('Usage fee must be positive');

    const burnPortion = (feeMstc * this.params.burnFeeSharePercent) / 100;
    const insurancePortion = (feeMstc * this.params.insuranceFeeSharePercent) / 100;
    const validatorPortion = (feeMstc * this.params.validatorRewardSharePercent) / 100;

    // Simulate SST burn (assuming 1 MSTC = 10 SST equivalent)
    const sstBurned = burnPortion * 10;
    this.state.sstTotalBurned += sstBurned;
    this.state.sstCirculatingSupply = Math.max(0, this.state.sstCirculatingSupply - sstBurned);

    this.state.insuranceTreasuryBalanceMstc += insurancePortion;
    this.state.totalUsageFeesProcessedMstc += feeMstc;

    this.recalculateAdaptiveEmission();

    return {
      burnedSst: sstBurned,
      insuranceAddedMstc: insurancePortion,
      validatorRewardsMstc: validatorPortion,
    };
  }

  /**
   * Slashes a misbehaving or compromised Public Domain node.
   * Diverts slashed stake directly into the Insurance Treasury.
   */
  public slashNode(
    nodeId: string,
    reason: SlashingEvent['reason'],
    nodeStakedSst: number
  ): SlashingEvent {
    const slashPercent = this.params.slashingPenaltyPercent;
    const slashedSst = (nodeStakedSst * slashPercent) / 100;

    this.state.stakedSst = Math.max(0, this.state.stakedSst - slashedSst);
    // Divert into insurance treasury (assuming 10 SST = 1 MSTC)
    const insuranceMstc = slashedSst / 10;
    this.state.insuranceTreasuryBalanceMstc += insuranceMstc;

    const event: SlashingEvent = {
      id: `slash-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      nodeId,
      reason,
      slashedAmountSst: slashedSst,
      divertedToInsuranceTreasury: insuranceMstc,
      timestamp: new Date().toISOString(),
    };

    this.slashingHistory.push(event);
    this.recalculateAdaptiveEmission();
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

