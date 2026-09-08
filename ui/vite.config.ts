import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  server: {
    port: 5173,
    strictPort: true,
    watch: {
      // Tauri builds Rust artifacts here. Watching its transient Windows .exe
      // files races with rustc and can make Node's fs watcher fail with EBUSY.
      ignored: ['**/src-tauri/target/**']
    }
  }
});
