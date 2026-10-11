/** Design tokens: slate surfaces, one steel-blue accent, semantic colours reserved for status. */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0e1218", panel: "#141922", raised: "#1a212d", rule: "#262e3d", hover: "#1f2735",
        text: "#d9dfeb", dim: "#8691a6", faint: "#5d687c",
        gate: "#6ea8fe", ok: "#56c596", warn: "#e3b05a", deny: "#ec7272",
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
