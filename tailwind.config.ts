import type { Config } from 'tailwindcss'

export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        severity: {
          critical: '#E24B4A',
          high: '#EF9F27',
          medium: '#378ADD',
          low: '#639922',
        },
        accent: {
          DEFAULT: '#185FA5',
          dark: '#114375',
          light: '#2479CC',
        },
      },
    },
  },
  plugins: [],
} satisfies Config
