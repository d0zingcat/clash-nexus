import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"

export default defineConfig({
  base: "/static/",
  plugins: [react()],
  root: "web",
  build: {
    outDir: "../internal/web/static",
    emptyOutDir: true,
  },
})
