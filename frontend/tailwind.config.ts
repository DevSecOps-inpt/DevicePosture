import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
    "./hooks/**/*.{ts,tsx}"
  ],
  theme: {
    extend: {
      colors: {
        shell: "#0f1720",
        panel: "#151f2c",
        border: "#263243",
        muted: "#7b8a9f",
        accent: "#0f766e",
        accentSoft: "#103536",
        success: "#16a34a",
        warning: "#d97706",
        danger: "#dc2626",
        info: "#0284c7"
      },
      boxShadow: {
        panel: "0 20px 60px rgba(2, 8, 23, 0.28)"
      },
      backgroundImage: {
        grid: "radial-gradient(circle at top, rgba(15,118,110,0.18), transparent 28%), linear-gradient(rgba(38,50,67,0.28) 1px, transparent 1px), linear-gradient(90deg, rgba(38,50,67,0.28) 1px, transparent 1px)"
      },
      backgroundSize: {
        grid: "auto, 32px 32px, 32px 32px"
      }
    }
  },
  plugins: []
};

export default config;
