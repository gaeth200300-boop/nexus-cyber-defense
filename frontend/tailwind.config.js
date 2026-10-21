/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["class", '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        bg: "rgb(var(--bg) / <alpha-value>)",
        panel: "rgb(var(--panel) / <alpha-value>)",
        panel2: "rgb(var(--panel2) / <alpha-value>)",
        panel3: "rgb(var(--panel3) / <alpha-value>)",
        ink: "rgb(var(--ink) / <alpha-value>)",
        muted: "rgb(var(--muted) / <alpha-value>)",
        faint: "rgb(var(--faint) / <alpha-value>)",
        line: "rgb(var(--line) / <alpha-value>)",
        accent: "rgb(var(--accent) / <alpha-value>)",
        accent2: "rgb(var(--accent2) / <alpha-value>)",
        ok: "rgb(var(--ok) / <alpha-value>)",
        warn: "rgb(var(--warn) / <alpha-value>)",
        danger: "rgb(var(--danger) / <alpha-value>)"
      },
      fontFamily: {
        sans: ["Space Grotesk", "IBM Plex Sans Arabic", "Segoe UI", "sans-serif"],
        arabic: ["IBM Plex Sans Arabic", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "Cascadia Code", "monospace"]
      },
      boxShadow: {
        glow: "0 0 0 1px rgb(var(--accent) / .18), 0 20px 60px -20px rgb(var(--accent) / .35)",
        panel: "0 24px 80px -36px rgba(0,0,0,.85)",
        soft: "0 10px 40px -20px rgba(0,0,0,.7)"
      },
      borderRadius: {
        xl2: "1.15rem"
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0", transform: "translateY(6px)" },
          to: { opacity: "1", transform: "translateY(0)" }
        },
        "scale-in": {
          from: { opacity: "0", transform: "scale(.97)" },
          to: { opacity: "1", transform: "scale(1)" }
        },
        shimmer: {
          "100%": { transform: "translateX(100%)" }
        },
        pulseSoft: {
          "0%,100%": { opacity: "0.55" },
          "50%": { opacity: "1" }
        },
        scanline: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" }
        },
        drift: {
          "0%,100%": { transform: "translate3d(0,0,0)" },
          "50%": { transform: "translate3d(0,-12px,0)" }
        }
      },
      animation: {
        "fade-in": "fade-in .35s ease-out both",
        "scale-in": "scale-in .25s ease-out both",
        shimmer: "shimmer 1.8s infinite",
        "pulse-soft": "pulseSoft 2.4s ease-in-out infinite",
        scanline: "scanline 6s linear infinite",
        drift: "drift 8s ease-in-out infinite"
      }
    }
  },
  plugins: []
};
