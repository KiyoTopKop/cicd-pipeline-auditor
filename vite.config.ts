import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/pipelint/',
  server: {
    port: 8081,
    host: '0.0.0.0'
  },
  optimizeDeps: {
    include: ['yaml']
  }
})
