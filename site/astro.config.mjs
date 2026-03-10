import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://vellaveto.online',
  output: 'static',
  build: {
    assets: '_assets',
  },
});
