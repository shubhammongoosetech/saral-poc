import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './hooks/useAuth';
import { Navbar } from './components/Navbar';
import { Login } from './pages/Login';
import { Mfa } from './pages/Mfa';
import { WorkingPolicy } from './pages/WorkingPolicy';
import { Review } from './pages/Review';
import { Wallet } from './pages/Wallet';
import { ActivityLog } from './pages/ActivityLog';
import { Settings } from './pages/Settings';

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <div className="app-container">
          <Navbar />
          <main className="main-content">
            <Routes>
              <Route path="/" element={<Navigate to="/wallet" replace />} />
              <Route path="/login" element={<Login />} />
              <Route path="/mfa" element={<Mfa />} />
              <Route path="/working-policy" element={<WorkingPolicy />} />
              <Route path="/review" element={<Review />} />
              <Route path="/wallet" element={<Wallet />} />
              <Route path="/activity" element={<ActivityLog />} />
              <Route path="/settings" element={<Settings />} />

              {/* Redirect old routes to their new places in Settings */}
              <Route path="/devices" element={<Navigate to="/settings" replace />} />
              <Route path="/topology" element={<Navigate to="/settings" replace />} />
              <Route path="/recovery" element={<Navigate to="/settings" replace />} />
              <Route path="/security" element={<Navigate to="/settings" replace />} />

              {/* Fallback */}
              <Route path="*" element={<Navigate to="/wallet" replace />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </AuthProvider>
  );
};

export default App;
