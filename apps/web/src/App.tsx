import React, { useState } from 'react';
import { SessionProvider, useSession } from './context/SessionContext';
import { WelcomeLoginView } from './components/views/WelcomeLoginView';
import { OtpVerificationView } from './components/views/OtpVerificationView';
import { MfaView } from './components/views/MfaView';
import { WorkingPolicyView } from './components/views/WorkingPolicyView';
import { WalletCreateProgressView } from './components/views/WalletCreateProgressView';
import { WalletCreatedSuccessView } from './components/views/WalletCreatedSuccessView';
import { WalletHomeView } from './components/views/WalletHomeView';
import { SettingsView } from './components/views/SettingsView';
import { AccessRestrictedView } from './components/views/AccessRestrictedView';

const MainApp: React.FC = () => {
  const { gate, activeOtpMobile } = useSession();
  const [activeTab, setActiveTab] = useState<'wallet' | 'settings'>('wallet');
  const [showCreationSuccess, setShowCreationSuccess] = useState(false);

  if (gate === 'loading') {
    return (
      <div className="min-h-screen bg-bg flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-accent text-accent-contrast flex items-center justify-center font-bold text-lg animate-pulse select-none shadow-sm">
            S
          </div>
          <span className="text-xs font-mono text-muted tracking-wider">SARAL Protocol V3</span>
        </div>
      </div>
    );
  }

  // Gate 1: Anonymous (Welcome / Login or OTP Verification)
  if (gate === 'anonymous') {
    if (activeOtpMobile) {
      return <OtpVerificationView />;
    }
    return <WelcomeLoginView />;
  }

  // Gate 2: Second-Factor MFA
  if (gate === 'needs-mfa') {
    return <MfaView />;
  }

  // Gate 3: Working Policy Setup
  if (gate === 'needs-policy') {
    return <WorkingPolicyView />;
  }

  // Gate 4: Policy Access Denied
  if (gate === 'access-restricted') {
    return <AccessRestrictedView />;
  }

  // Gate 5: First-Time Wallet Creation
  if (gate === 'creating-wallet') {
    return <WalletCreateProgressView onComplete={() => setShowCreationSuccess(true)} />;
  }

  // First-time success splash before landing on Wallet Home
  if (showCreationSuccess) {
    return <WalletCreatedSuccessView onComplete={() => setShowCreationSuccess(false)} />;
  }

  // Gate 6: Authenticated Wallet Home & Settings
  if (activeTab === 'settings') {
    return <SettingsView onNavigateToWallet={() => setActiveTab('wallet')} />;
  }

  return <WalletHomeView onNavigateToSettings={() => setActiveTab('settings')} />;
};

export function App() {
  return (
    <SessionProvider>
      <MainApp />
    </SessionProvider>
  );
}

export default App;
