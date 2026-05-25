/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        background: '#111111',
        surface: '#1a1a1a',
        'surface-2': '#202020',
        sidebar: '#09090A',
        border: '#222222',
        muted: '#3a3a3a',
        foreground: '#f0f0f0',
        'foreground-muted': '#888888',
        accent: '#22C55E',
        'accent-dim': '#166534',
        danger: '#EF4444',
        'danger-dim': '#7F1D1D',
        warning: '#F59E0B',
        'warning-dim': '#78350F',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}
