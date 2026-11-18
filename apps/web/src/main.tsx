import React from 'react';
import ReactDOM from 'react-dom/client';
import '@fontsource-variable/inter';
import { App } from './App';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import './styles/index.css';

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
