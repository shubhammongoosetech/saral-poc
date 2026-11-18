import { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): State {
    return {
      hasError: true,
      error,
      errorInfo: null,
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[SARAL ErrorBoundary] Uncaught runtime exception:', error, errorInfo);
    this.setState({ errorInfo });
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.reload();
  };

  handleLogout = () => {
    try {
      localStorage.removeItem('saral_session_token');
    } catch (_) {}
    window.location.href = '/';
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="min-h-screen bg-bg flex items-center justify-center p-6 font-sans selection:bg-danger/20 text-text">
          <div className="w-full max-w-md bg-surface border border-border rounded-2xl p-6 sm:p-8 shadow-sm flex flex-col items-center gap-5 text-center">
            {/* Warning icon */}
            <div className="w-14 h-14 rounded-2xl bg-danger/10 text-danger border border-danger/20 flex items-center justify-center text-2xl select-none">
              ⚠️
            </div>

            <div className="flex flex-col gap-1.5">
              <h1 className="text-lg font-bold text-text tracking-tight">Application Encountered an Error</h1>
              <p className="text-xs text-muted leading-relaxed">
                A runtime exception occurred while rendering the SARAL Wallet interface. The application has safely halted to protect cryptographic state.
              </p>
            </div>

            {/* Error detail box */}
            <div className="w-full p-3.5 rounded-xl bg-danger/5 border border-danger/20 text-left flex flex-col gap-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-danger">Error Description:</span>
              <p className="font-mono text-xs text-danger break-words leading-relaxed">
                {this.state.error?.message || 'Unknown runtime error'}
              </p>
              {this.state.errorInfo?.componentStack && (
                <details className="mt-1">
                  <summary className="text-[10px] text-muted cursor-pointer hover:text-text">Component stack trace</summary>
                  <pre className="text-[9px] font-mono text-muted overflow-x-auto max-h-32 mt-1 p-2 bg-surface rounded border border-border">
                    {this.state.errorInfo.componentStack}
                  </pre>
                </details>
              )}
            </div>

            {/* Action buttons */}
            <div className="w-full flex gap-3 pt-2">
              <button
                type="button"
                onClick={this.handleLogout}
                className="flex-1 h-11 border border-border text-text rounded-xl text-xs font-semibold hover:bg-surface-2 transition-colors cursor-pointer"
              >
                Log Out & Reset
              </button>
              <button
                type="button"
                onClick={this.handleReset}
                className="flex-1 h-11 bg-accent text-accent-contrast rounded-xl text-xs font-semibold hover:bg-accent-hover transition-colors cursor-pointer flex items-center justify-center gap-1.5"
              >
                Reload Application ↻
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
export default ErrorBoundary;
