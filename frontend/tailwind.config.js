/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['IBM Plex Sans', 'ui-sans-serif', 'system-ui'],
        mono: ['IBM Plex Mono', 'ui-monospace', 'SFMono-Regular'],
      },
      colors: {
        primary: {
          50: '#f8f9fa',
          100: '#e9ecef',
          200: '#dee2e6',
          300: '#ced4da',
          400: '#adb5bd',
          500: '#6c757d',
          600: '#495057',
          700: '#343a40',
          800: '#212529',
          900: '#000000',
        },
        success: {
          50: '#d4edda',
          500: '#28a745',
          600: '#1e7e34',
        },
        warning: {
          50: '#fff3cd',
          500: '#ffc107',
          600: '#e0a800',
        },
        error: {
          50: '#f8d7da',
          500: '#dc3545',
          600: '#c82333',
        },
        info: {
          50: '#d1ecf1',
          500: '#17a2b8',
          600: '#138496',
        }
      },
    },
  },
  plugins: [],
};

