import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  build: {
    // Emitted straight into the package the backend serves as static files.
    outDir: '../backend/app/static',
    emptyOutDir: true,
    chunkSizeWarningLimit: 900,
  },
  server: {
    port: 5173,
    proxy: {
      // Dev server talks to the backend so cookies are same-origin.
      '/api': { target: 'http://localhost:8000', changeOrigin: true },
      '/npm': { target: 'http://localhost:8000', changeOrigin: true },
      '/pypi': { target: 'http://localhost:8000', changeOrigin: true },
      '/health': { target: 'http://localhost:8000', changeOrigin: true },
    },
  },
})
