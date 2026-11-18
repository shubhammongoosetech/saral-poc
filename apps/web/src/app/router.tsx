import React from 'react';
import { createBrowserRouter, Navigate, Outlet } from 'react-router-dom';
import { RequireAuth } from './guards/RequireAuth';
import { RequireMfa } from './guards/RequireMfa';
import { RequirePolicy } from './guards/RequirePolicy';
import { PublicOnly } from './guards/PublicOnly';
import { resolveGate } from './guards/resolveGate';
import { useSession, SessionProvider } from '@/features/auth/useSession';

// Lazy-loaded pages
const Login = React.lazy(() => import('@/features/auth/Login').then((m) => ({ default: m.Login })));
const Mfa = React.lazy(() => import('@/features/auth/Mfa').then((m) => ({ default: m.Mfa })));
const WorkingPolicy = React.lazy(() =>
  import('@/features/policy/WorkingPolicy').then((m) => ({ default: m.WorkingPolicy }))
);
const Review = React.lazy(() => import('@/features/policy/Review').then((m) => ({ default: m.Review })));
const Wallet = React.lazy(() => import('@/features/wallet/Wallet').then((m) => ({ default: m.Wallet })));
const Activity = React.lazy(() => import('@/features/activity/Activity').then((m) => ({ default: m.Activity })));
const Settings = React.lazy(() => import('@/features/settings/Settings').then((m) => ({ default: m.Settings })));

// Layouts
const AppLayout = React.lazy(() => import('./layouts/AppLayout').then((m) => ({ default: m.AppLayout })));

const SessionLayout: React.FC = () => {
  return (
    <SessionProvider>
      <Outlet />
    </SessionProvider>
  );
};

const RootRedirect: React.FC = () => {
  const { status } = useSession();
  if (status === 'loading') {
    return <div className="min-h-screen bg-bg" />;
  }
  return <Navigate to={resolveGate(status)} replace />;
};

export const router = createBrowserRouter([
  {
    element: <SessionLayout />,
    children: [
      {
        path: '/',
        element: <RootRedirect />,
      },
      // Public-only route (/login)
      {
        element: <PublicOnly />,
        children: [
          {
            path: '/login',
            element: (
              <React.Suspense fallback={<div className="min-h-screen bg-bg" />}>
                <Login />
              </React.Suspense>
            ),
          },
        ],
      },
      // MFA route (/mfa)
      {
        element: <RequireMfa />,
        children: [
          {
            path: '/mfa',
            element: (
              <React.Suspense fallback={<div className="min-h-screen bg-bg" />}>
                <Mfa />
              </React.Suspense>
            ),
          },
        ],
      },
      // Working Policy route (/working-policy)
      {
        element: <RequirePolicy />,
        children: [
          {
            path: '/working-policy',
            element: (
              <React.Suspense fallback={<div className="min-h-screen bg-bg" />}>
                <WorkingPolicy />
              </React.Suspense>
            ),
          },
        ],
      },
      // Protected wallet app routes
      {
        element: <RequireAuth />,
        children: [
          {
            path: '/review',
            element: (
              <React.Suspense fallback={<div className="min-h-screen bg-bg" />}>
                <Review />
              </React.Suspense>
            ),
          },
          {
            element: (
              <React.Suspense fallback={<div className="min-h-screen bg-bg" />}>
                <AppLayout />
              </React.Suspense>
            ),
            children: [
              {
                path: '/wallet',
                element: (
                  <React.Suspense fallback={<div className="p-6" />}>
                    <Wallet />
                  </React.Suspense>
                ),
              },
              {
                path: '/activity',
                element: (
                  <React.Suspense fallback={<div className="p-6" />}>
                    <Activity />
                  </React.Suspense>
                ),
              },
              {
                path: '/settings',
                element: (
                  <React.Suspense fallback={<div className="p-6" />}>
                    <Settings />
                  </React.Suspense>
                ),
              },
            ],
          },
        ],
      },
      // Catch-all route
      {
        path: '*',
        element: <RootRedirect />,
      },
    ],
  },
]);
