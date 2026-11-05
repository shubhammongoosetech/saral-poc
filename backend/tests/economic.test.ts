/**
 * economic.test.ts
 *
 * Adaptive Multi-Asset Economic Security Layer Test Suite.
 *
 * Patent & Specification Mandates (Claims 6-10, 12, Paragraphs [0023]-[0030]):
 *   1. Fixed-supply MSTC (8,000,000,000 base tokens) with zero mint capability.
 *   2. Restaking Vault: 1:1 sMSTC minted against deposited MSTC.
 *   3. SST hard supply ceiling (100,000,000 SST) and staking limits.
 *   4. Security Ratio R = TVS / (Staked SST + Staked sMSTC).
 *   5. Adaptive issuance APR scaling based on R relative to target R*.
 *   6. Fee Router: Usage fees split into SST burn, Insurance reserve, and validator yield.
 *   7. Slashing: 60% diverted to Insurance Treasury, 40% to Validator Redistribution.
 *   8. Joint Governance: Two-Signature Rule (Foundation + Public signatures required).
 */

import test from 'node:test';
import assert from 'node:assert';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

process.env.NODE_ENV = 'test';

// Remove any residual state file from previous runs
const testStateFile = path.resolve(process.cwd(), '.saral_registry', 'economic_state.json');
if (fs.existsSync(testStateFile)) {
  try { fs.unlinkSync(testStateFile); } catch {}
}

import { secp256k1 } from '@noble/curves/secp256k1';

import { EconomicSecuritySubsystem } from '../src/services/economicService';
import { randomScalar, scalarMultiplyG } from '../src/crypto/secp256k1Math';

test('1. Fixed Supply Invariants & Initial Calibrated Parameters', () => {
  const econ = new EconomicSecuritySubsystem();
  const params = econ.getParameters();

  assert.strictEqual(params.mstcTotalFixedSupply, 8_000_000_000, 'MSTC fixed supply must be 8B');
  assert.strictEqual(params.sstMaxSupplyCeiling, 100_000_000, 'SST supply cap must be 100M');
  assert.strictEqual(params.slashingInsuranceSplitPercent, 60, 'Slashing insurance split must be 60%');
  assert.strictEqual(params.slashingRedistributionSplitPercent, 40, 'Slashing redistribution split must be 40%');
});

test('2. Restaking Vault: 1:1 sMSTC minting and redemption', () => {
  const econ = new EconomicSecuritySubsystem();
  const state0 = econ.getState();
  const initialSmstc = state0.stakedSmstc;

  // Deposit 1,000,000 MSTC into restaking vault
  const { mintedSmstc, newTes } = econ.restakeMstc(1_000_000, 'user-restake-01');
  assert.strictEqual(mintedSmstc, 1_000_000, 'Must mint exactly 1:1 sMSTC');
  assert.strictEqual(econ.getState().stakedSmstc, initialSmstc + 1_000_000);

  // Redeem 400,000 sMSTC back to MSTC
  const { redeemedMstc } = econ.redeemSmstc(400_000, 'user-restake-01');
  assert.strictEqual(redeemedMstc, 400_000, 'Must redeem exactly 1:1 back to MSTC');
  assert.strictEqual(econ.getState().stakedSmstc, initialSmstc + 600_000);

  // Overdraft redemption must fail
  assert.throws(
    () => econ.redeemSmstc(1_000_000, 'user-restake-01'),
    /Insufficient sMSTC balance/i,
    'Cannot redeem more sMSTC than deposited'
  );
});

test('3. SST Supply Ceiling & Hard Cap Enforcement', () => {
  const econ = new EconomicSecuritySubsystem();

  // Staking within circulating supply succeeds
  const { newStakedSst } = econ.stakeSst(5_000_000);
  assert.strictEqual(newStakedSst, 30_000_000);

  // Staking beyond circulating supply fails
  assert.throws(
    () => econ.stakeSst(100_000_000),
    /exceeds circulating SST supply/i,
    'Cannot stake more SST than exists in circulation'
  );
});

test('4. Security Ratio R and Adaptive Emission APR Engine', () => {
  const econ = new EconomicSecuritySubsystem();
  // Baseline: TVS = 50M, TES = 25M (SST) + 15M (sMSTC) = 40M. R = 50 / 40 = 1.25 (well collateralized, below R*=1.5)
  const baseline = econ.getState();
  assert.strictEqual(baseline.currentSecurityRatio, 1.25);
  assert.ok(baseline.currentEmissionRateApr <= 0.05);

  // Increase TVS to 120M (Under-collateralized: R = 120 / 40 = 3.0 > R*=1.5)
  econ.updateTvs(120_000_000);
  const stressed = econ.getState();
  assert.strictEqual(stressed.currentSecurityRatio, 3.0);
  // Emission APR must increase up to max ceiling (15%)
  assert.strictEqual(stressed.currentEmissionRateApr, 0.15, 'Emission APR must hit bounded ceiling of 15%');

  // Node deposits collateral, reducing R
  econ.restakeMstc(60_000_000);
  const restored = econ.getState();
  assert.ok(restored.currentSecurityRatio < 3.0);
  assert.ok(restored.currentEmissionRateApr < 0.15, 'Emission APR must decay as collateral is added');
});

test('5. Protocol Fee Router: 30% SST Burn, 20% Insurance, 50% Validator Yield', () => {
  const econ = new EconomicSecuritySubsystem();
  const initialInsurance = econ.getState().insuranceTreasuryBalanceMstc;
  const initialBurned = econ.getState().sstTotalBurned;

  // Process 10,000 MSTC protocol fee
  const result = econ.processUsageFee(10_000);

  // 20% = 2,000 MSTC to Insurance
  assert.strictEqual(result.insuranceAddedMstc, 2_000);
  assert.strictEqual(econ.getState().insuranceTreasuryBalanceMstc, initialInsurance + 2_000);

  // 30% = 3,000 MSTC burned as SST via oracle (rate 10 -> 30,000 SST burned)
  assert.strictEqual(result.burnedSst, 30_000);
  assert.strictEqual(econ.getState().sstTotalBurned, initialBurned + 30_000);

  // 50% = 5,000 MSTC to Validator Rewards
  assert.strictEqual(result.validatorRewardsMstc, 5_000);
});

test('6. Slashing Dual-Split: 60% Insurance Treasury, 40% Validator Redistribution', () => {
  const econ = new EconomicSecuritySubsystem();
  const initialInsurance = econ.getState().insuranceTreasuryBalanceMstc;
  const initialPool = econ.getState().validatorRedistributionPoolMstc;

  // Slash Byzantine node with 1,000,000 staked SST (10% slash penalty = 100,000 SST slashed)
  // 100,000 SST at oracle rate 10 = 10,000 MSTC equivalent
  // 60% (6,000 MSTC) -> Insurance Treasury, 40% (4,000 MSTC) -> Redistribution Pool
  const slashEvent = econ.slashNode('saral-public-malicious-1', 'EQUIVOCATION', 1_000_000);

  assert.strictEqual(slashEvent.slashedAmountSst, 100_000);
  assert.strictEqual(slashEvent.divertedToInsuranceTreasury, 6_000);
  assert.strictEqual(slashEvent.redistributedToValidators, 4_000);

  assert.strictEqual(econ.getState().insuranceTreasuryBalanceMstc, initialInsurance + 6_000);
  assert.strictEqual(econ.getState().validatorRedistributionPoolMstc, initialPool + 4_000);
});

test('7. Joint Governance (Patent Claims 8, 12): Two-Signature Rule', () => {
  const econ = new EconomicSecuritySubsystem();

  // Generate Foundation and Public authority keypairs
  const fPriv = randomScalar();
  const fPub = scalarMultiplyG(fPriv).toHex(true);

  const pPriv = randomScalar();
  const pPub = scalarMultiplyG(pPriv).toHex(true);

  const proposedParams = { targetSecurityRatio: 2.0, maxEmissionRateApr: 0.18 };
  const canonicalPayload = JSON.stringify(proposedParams);
  const hash = crypto.createHash('sha256').update(`GOVERNANCE_PARAM_UPDATE:${canonicalPayload}`).digest();

  const fSig = secp256k1.sign(hash, fPriv.toString(16).padStart(64, '0')).toCompactHex();
  const pSig = secp256k1.sign(hash, pPriv.toString(16).padStart(64, '0')).toCompactHex();

  // Valid two-signature update
  const updated = econ.updateGovernanceParameters(proposedParams, fSig, pSig, fPub, pPub);
  assert.strictEqual(updated.targetSecurityRatio, 2.0);
  assert.strictEqual(updated.maxEmissionRateApr, 0.18);

  // Invalid signature from Foundation fails
  const badPriv = randomScalar();
  const badSig = secp256k1.sign(hash, badPriv.toString(16).padStart(64, '0')).toCompactHex();

  assert.throws(
    () => econ.updateGovernanceParameters(proposedParams, badSig, pSig, fPub, pPub),
    /Foundation domain authorization signature is invalid/i,
    'Invalid Foundation signature must reject governance parameter update'
  );

  // Invalid signature from Public domain fails
  assert.throws(
    () => econ.updateGovernanceParameters(proposedParams, fSig, badSig, fPub, pPub),
    /Public validator domain authorization signature is invalid/i,
    'Invalid Public domain signature must reject governance parameter update'
  );
});
