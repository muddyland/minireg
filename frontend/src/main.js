import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import './style.css'

// Apply the stored theme before mount so there is no light-mode flash.
const stored = localStorage.getItem('minireg-theme')
if (stored) {
  document.documentElement.setAttribute('data-theme', stored)
} else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
  document.documentElement.setAttribute('data-theme', 'dark')
}

createApp(App).use(createPinia()).use(router).mount('#app')
