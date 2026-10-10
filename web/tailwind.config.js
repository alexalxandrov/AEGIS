/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        graphite: {
          DEFAULT: "#0f1214",
          panel: "#151a1d",
          elevated: "#1a1f22",
          border: "#2a3238",
        },
        accent: {
          DEFAULT: "#3dbeb0",
          muted: "#2a9d92",
          dim: "#1f756d",
        },
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
