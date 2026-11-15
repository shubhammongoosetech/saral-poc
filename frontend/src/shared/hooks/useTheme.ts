import { useState, useEffect } from 'react';

export type Theme = 'light' | 'dark';

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(() => {
    try {
      const saved = localStorage.getItem('saral-theme');
      if (saved === 'dark' || saved === 'light') return saved;
    } catch {}
    return 'light'; // Default to light
  });

  const setTheme = (nextTheme: Theme) => {
    setThemeState(nextTheme);
    try {
      localStorage.setItem('saral-theme', nextTheme);
      document.documentElement.setAttribute('data-theme', nextTheme);
      document.documentElement.style.colorScheme = nextTheme;
    } catch {}
  };

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    document.documentElement.style.colorScheme = theme;
  }, [theme]);

  return { theme, setTheme };
}
