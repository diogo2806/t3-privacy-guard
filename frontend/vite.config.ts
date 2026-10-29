import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  // In production the backend serves dist from the same origin; in development the dev server forwards /api to it.
  const backendUrl = loadEnv(mode, process.cwd()).VITE_BACKEND_URL || 'http://localhost:8080';
  return {
    plugins: [react()],
    server: {
      proxy: {
        '/api': { target: backendUrl, changeOrigin: true },
        // Single sign-on starts and returns on the backend.
        '/oauth2': { target: backendUrl, changeOrigin: true },
        '/login/oauth2': { target: backendUrl, changeOrigin: true },
      },
    },
    test: {
      setupFiles: ['./src/test/setup.ts'],
      // Interaction tests type character by character; shared CI runners need more than the 5 s default.
      testTimeout: 15000,
    },
  };
});
