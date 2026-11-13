import React, { useState, useCallback } from 'react';
import {
  TransactionPreview,
  SignAndSendOptions,
  SignAndSendResult,
  DomainName,
  SaralError,
  PrepareTransactionRequest,
} from '@saral/sdk-core';
import { usePrepareTransaction } from './hooks/usePrepareTransaction';
import { useSignAndSend, SignFlowState } from './hooks/useSignAndSend';

export interface SendFlowRenderProps {
  state: SignFlowState;
  signingDomain: DomainName | null;
  preview: TransactionPreview | null;
  prepare: (overrideReq?: Partial<PrepareTransactionRequest>) => Promise<TransactionPreview>;
  confirmAndSign: (opts?: SignAndSendOptions) => Promise<SignAndSendResult>;
  result: SignAndSendResult | null;
  error: SaralError | null;
  reset: () => void;
}

export interface SendFlowProps {
  chain: string;
  to: string;
  amount: string;
  memo?: string;
  children: (props: SendFlowRenderProps) => React.ReactNode;
}

/**
 * Headless render-prop component orchestrating the complete Payment & 3-Domain Signing flow.
 * Implements Zero-Styling policy — pure logic and state machine.
 */
export const SendFlow: React.FC<SendFlowProps> = ({
  chain,
  to,
  amount,
  memo,
  children,
}) => {
  const { prepare: execPrepare, preview, reset: resetPrepare, error: prepareError } = usePrepareTransaction();
  const {
    state,
    signingDomain,
    result,
    error: signError,
    execute: execSign,
    reset: resetSign,
  } = useSignAndSend();

  const [activePreview, setActivePreview] = useState<TransactionPreview | null>(null);

  const handlePrepare = useCallback(
    async (overrideReq?: Partial<PrepareTransactionRequest>) => {
      const prev = await execPrepare({
        chain: overrideReq?.chain || chain,
        to: overrideReq?.to || to,
        amount: overrideReq?.amount || amount,
        memo: overrideReq?.memo || memo,
      });
      setActivePreview(prev);
      return prev;
    },
    [execPrepare, chain, to, amount, memo]
  );

  const handleConfirmAndSign = useCallback(
    async (opts?: SignAndSendOptions) => {
      let targetPreview = activePreview || preview;
      if (!targetPreview) {
        targetPreview = await handlePrepare();
      }
      return execSign(targetPreview, opts);
    },
    [activePreview, preview, handlePrepare, execSign]
  );

  const handleReset = useCallback(() => {
    resetPrepare();
    resetSign();
    setActivePreview(null);
  }, [resetPrepare, resetSign]);

  const activeError = signError || prepareError;

  return (
    <>
      {children({
        state,
        signingDomain,
        preview: activePreview || preview,
        prepare: handlePrepare,
        confirmAndSign: handleConfirmAndSign,
        result,
        error: activeError,
        reset: handleReset,
      })}
    </>
  );
};

