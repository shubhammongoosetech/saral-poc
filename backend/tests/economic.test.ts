import test from 'node:test';
import assert from 'node:assert';
import { EconomicSecuritySubsystem } from '../src/services/economicService';

test('1. Security Ratio Calculation: R = TVS / TES', () => {
  const econ = new EconomicSecuritySubsystem({
    targetSecurityRatio: 1.5,
    minEmissionRateApr: 0.02,
    maxEmissionRateApr: 0.15,
  });

  const state1 = econ.getState();
  // Initially TVS = 50M, Staked SST = 25M, Staked sMSTC = 15M -> TES = 40M
  // R = 50 / 40 = 1.25
  assert.strictEqual(state1.totalEffectiveStake, 40_000_000);
  assert.strictEqual(state1.currentSecurityRatio, 1.25);

  // Increase TVS to 80M -> R = 80 / 40 = 2.0
  const state2 = econ.updateTvs(80_000_000);
  assert.strictEqual(state2.currentSecurityRatio, 2.0);
});

test('2. Restaking & Derivative Accounting: sMSTC minted 1:1 against MSTC', () => {
  const econ = new EconomicSecuritySubsystem();
  const initialTes = econ.getState().totalEffectiveStake;

  const result = econ.restakeMstc(5_000_000);
  assert.strictEqual(result.mintedSmstc, 5_000_000);
  assert.strictEqual(result.newTes, initialTes + 5_000_000);
});

test('3. Adaptive Issuance Engine: Bounded Annual Emission Modulation', () => {
  const econ = new EconomicSecuritySubsystem({
    targetSecurityRatio: 1.5,
    minEmissionRateApr: 0.02,
    maxEmissionRateApr: 0.15,
  });

  // When R = 1.25 <= R* (1.5), emission should be close to baseline
  const baselineState = econ.getState();
  assert.ok(baselineState.currentEmissionRateApr <= 0.05);

  // Under-collateralized stress scenario: TVS surges to 150M -> R = 150 / 40 = 3.75 >> R*
  const highRiskState = econ.updateTvs(150_000_000);
  assert.ok(highRiskState.currentSecurityRatio > 1.5);
  // Emission must automatically ramp up towards the maximum bounded ceiling (15%)
  assert.strictEqual(highRiskState.currentEmissionRateApr, 0.15);
});

test('4. Usage-Fee Processing: Burn-and-Mint, Insurance Treasury & Staking Yield', () => {
  const econ = new EconomicSecuritySubsystem();
  const initialTreasury = econ.getState().insuranceTreasuryBalanceMstc;
  const initialCirculating = econ.getState().sstCirculatingSupply;

  // Process 10,000 MSTC protocol fee
  const feeResult = econ.processUsageFee(10_000);

  // 30% burn = 3,000 MSTC equivalent in SST (30,000 SST)
  assert.strictEqual(feeResult.burnedSst, 30_000);
  // 20% insurance = 2,000 MSTC added to treasury
  assert.strictEqual(feeResult.insuranceAddedMstc, 2_000);
  // 50% validator yield = 5,000 MSTC
  assert.strictEqual(feeResult.validatorRewardsMstc, 5_000);

  const updatedState = econ.getState();
  assert.strictEqual(updatedState.insuranceTreasuryBalanceMstc, initialTreasury + 2_000);
  assert.strictEqual(updatedState.sstCirculatingSupply, initialCirculating - 30_000);
  assert.strictEqual(updatedState.sstTotalBurned, 30_000);
});

test('5. Slashing Mechanism & Adversarial Simulation', () => {
  const econ = new EconomicSecuritySubsystem();
  const initialTreasury = econ.getState().insuranceTreasuryBalanceMstc;

  // Slash a compromised Byzantine node with 200,000 SST stake (10% slash penalty = 20,000 SST)
  const slashEvent = econ.slashNode('public-node-byzantine-7', 'BYZANTINE_FAULT', 200_000);
  assert.strictEqual(slashEvent.slashedAmountSst, 20_000);
  assert.strictEqual(slashEvent.divertedToInsuranceTreasury, 2_000);

  const postSlashState = econ.getState();
  assert.strictEqual(postSlashState.insuranceTreasuryBalanceMstc, initialTreasury + 2_000);

  // Run multi-scenario stress simulation
  const simResults = econ.runStressSimulation([
    { name: 'Normal Traffic', tvsMultiplier: 1.0, slashNodesCount: 0 },
    { name: 'Moderate Growth', tvsMultiplier: 1.5, slashNodesCount: 1 },
    { name: 'High Volatility Stress', tvsMultiplier: 2.5, slashNodesCount: 3 },
  ]);

  assert.strictEqual(simResults.length, 3);
  for (const r of simResults) {
    assert.ok(r.securityRatio > 0);
    assert.ok(r.emissionApr >= 0.01 && r.emissionApr <= 0.15);
  }
});

