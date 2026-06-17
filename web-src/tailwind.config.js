/** @type {import('tailwindcss').Config} */
import forms from "@tailwindcss/forms";
import typography from "@tailwindcss/typography";
import plugin from "tailwindcss/plugin";

// 语义色映射到 CSS 变量（在 src/styles/app.css 的 :root / .dark 中定义），
// 便于后续暗色模式切换。brand 绿色基于 leanote 主色 #0fb264。
function withVar(name) {
  return `rgb(var(${name}) / <alpha-value>)`;
}

export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        brand: {
          50: "#e9f9f1",
          100: "#c9f0dd",
          200: "#94e2bd",
          300: "#5dd29c",
          400: "#2dbe7d",
          500: "#0fb264", // leanote @hColor
          600: "#0a9a55",
          700: "#097c46",
          800: "#0a6139",
          900: "#0a4f30",
          950: "#042c1b",
        },
        // 语义令牌
        bg: withVar("--c-bg"),
        surface: withVar("--c-surface"),
        elevated: withVar("--c-elevated"),
        border: withVar("--c-border"),
        fg: withVar("--c-fg"),
        muted: withVar("--c-muted"),
        subtle: withVar("--c-subtle"),
        accent: withVar("--c-accent"),
        "accent-fg": withVar("--c-accent-fg"),
      },
      fontFamily: {
        sans: [
          "Inter",
          "Open Sans",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "PingFang SC",
          "Hiragino Sans GB",
          "Microsoft YaHei",
          "WenQuanYi Micro Hei",
          "sans-serif",
        ],
        mono: ["JetBrains Mono", "Menlo", "Consolas", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px rgba(16,24,40,0.04), 0 1px 3px rgba(16,24,40,0.06)",
        pop: "0 8px 28px -6px rgba(16,24,40,0.18), 0 4px 12px -8px rgba(16,24,40,0.14)",
      },
      borderRadius: {
        xl: "0.75rem",
      },
    },
  },
  plugins: [
    forms,
    typography,
    // 触摸设备变体：用于让「hover 才显示」的行内操作在无 hover 的手机/平板上常驻可见。
    plugin(({ addVariant }) => {
      addVariant("touch", "@media (hover: none)");
    }),
  ],
};
