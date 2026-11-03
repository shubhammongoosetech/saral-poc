import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { Login } from './pages/Login';
import { Mfa } from './pages/Mfa';
import { WorkingPolicy } from './pages/WorkingPolicy';
import { Review } from './pages/Review';
import { Wallet } from './pages/Wallet';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <div className="app-container">
        <Navbar />
        <main className="main-content">
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/mfa" element={<Mfa />} />
            <Route path="/working-policy" element={<WorkingPolicy />} />
            <Route path="/review" element={<Review />} />
            <Route path="/wallet" element={<Wallet />} />
            <Route path="*" element={<Navigate to="/login" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
};

export default App;
