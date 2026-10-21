import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import { ar } from './locales/ar';
import { en } from './locales/en';

const stored = typeof localStorage !== 'undefined' ? localStorage.getItem('nexus.locale') : null;
const initialLocale = stored === 'en' ? 'en' : 'ar';

i18n.use(initReactI18next).init({
  resources: { ar, en },
  lng: initialLocale,
  fallbackLng: 'ar',
  supportedLngs: ['ar', 'en'],
  interpolation: { escapeValue: false },
  returnNull: false,
});

/** Apply document language + direction and remember the choice. */
export function applyDir(locale: string): void {
  const lang = locale === 'en' ? 'en' : 'ar';
  const dir = lang === 'ar' ? 'rtl' : 'ltr';
  document.documentElement.setAttribute('lang', lang);
  document.documentElement.setAttribute('dir', dir);
  localStorage.setItem('nexus.locale', lang);
}

applyDir(initialLocale);

export default i18n;
