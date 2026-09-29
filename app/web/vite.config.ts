import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// the dashboard builds into app/web/dist, which the fastapi app serves with app.frontend() and
// vercel promotes to its cdn (app/CLAUDE.md section 2); in development /api goes to uvicorn.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(__dirname, './src') } },
  build: {
    outDir: path.resolve(__dirname, 'dist'),
    emptyOutDir: true,
    chunkSizeWarningLimit: 1200,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('echarts') || id.includes('zrender')) return 'charts'
          if (id.includes('node_modules')) return 'vendor'
        },
      },
    },
  },
  server: { port: 5173, proxy: { '/api': 'http://127.0.0.1:8000', '/agent': 'http://127.0.0.1:8000' } },
})
