import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://www.vellaveto.online',
  output: 'static',
  build: {
    assets: '_assets',
  },
});
