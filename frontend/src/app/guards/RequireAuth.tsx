import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useSession } from '@/features/auth/useSession';
import { resolveGate } from './resolveGate';

export const RequireAuth: React.FC = () => {
  const { status } = useSession();

  if (status === 'loading') {
    return (
      <div className="min-h-screen bg-bg flex items-center justify-center p-6">
        <div className="w-full max-w-sm flex flex-col gap-4">
          <div className="h-8 bg-surface-2 rounded-md animate-pulse" />
          <div className="h-40 bg-surface-2 rounded-xl animate-pulse" />
        </div>
      </div>
    );
  }

  if (status !== 'ready') {
    return <Navigate to={resolveGate(status)} replace />;
  }

  return <Outlet />;
};
