import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { getToken } from './api';

type Theme = 'dark' | 'light';
type Locale = 'ar' | 'en';

interface UiState {
  theme: Theme;
  locale: Locale;
  sidebarCollapsed: boolean;
  projectId: string | null;
  setTheme: (t: Theme) => void;
  toggleTheme: () => void;
  setLocale: (l: Locale) => void;
  toggleSidebar: () => void;
  setProjectId: (id: string | null) => void;
}

export const useUi = create<UiState>()(
  persist(
    (set, get) => ({
      theme: 'dark',
      locale: 'ar',
      sidebarCollapsed: false,
      projectId: null,
      setTheme: (t) => set({ theme: t }),
      toggleTheme: () => set({ theme: get().theme === 'dark' ? 'light' : 'dark' }),
      setLocale: (l) => set({ locale: l }),
      toggleSidebar: () => set({ sidebarCollapsed: !get().sidebarCollapsed }),
      setProjectId: (id) => set({ projectId: id }),
    }),
    { name: 'nexus-ui' }
  )
);

interface AuthState {
  user: any | null;
  bootstrapped: boolean | null;
  setUser: (u: any | null) => void;
  setBootstrapped: (b: boolean) => void;
  isAuthed: () => boolean;
}

export const useAuth = create<AuthState>()((set, get) => ({
  user: null,
  bootstrapped: null,
  setUser: (u) => set({ user: u }),
  setBootstrapped: (b) => set({ bootstrapped: b }),
  isAuthed: () => !!get().user && !!getToken(),
}));
