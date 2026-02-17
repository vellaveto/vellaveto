import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://vellaveto.dev',
  output: 'static',
  build: {
    assets: '_assets',
  },
});
