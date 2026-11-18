export type SessionStatus = 'loading' | 'anonymous' | 'needs-mfa' | 'needs-policy' | 'ready';

/**
 * Returns the default home path for a given session status.
 */
export function resolveGate(status: SessionStatus): string {
  switch (status) {
    case 'anonymous':
      return '/login';
    case 'needs-mfa':
      return '/mfa';
    case 'needs-policy':
      return '/working-policy';
    case 'ready':
      return '/wallet';
    case 'loading':
    default:
      return '/login';
  }
}

/**
 * Validates whether a specific route path is permitted for the active session status.
 */
export function isRouteAllowed(status: SessionStatus, path: string): boolean {
  const cleanPath = path.split('?')[0].split('#')[0];

  switch (status) {
    case 'anonymous':
      return cleanPath === '/login';

    case 'needs-mfa':
      return cleanPath === '/mfa';

    case 'needs-policy':
      return cleanPath === '/working-policy' || cleanPath === '/review';

    case 'ready':
      return (
        cleanPath === '/wallet' ||
        cleanPath === '/activity' ||
        cleanPath === '/settings' ||
        cleanPath === '/review' ||
        cleanPath === '/working-policy'
      );

    case 'loading':
    default:
      return false;
  }
}
