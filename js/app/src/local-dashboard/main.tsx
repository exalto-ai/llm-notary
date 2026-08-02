import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import {
  MantineProvider, createTheme, localStorageColorSchemeManager
} from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';
import './styles.css';
import { Dashboard } from './Dashboard';
import { localApi } from './api';
import { createFixtureApi } from './fixtures';

const colorSchemeManager = localStorageColorSchemeManager({ key: 'llm-notary-dashboard-color-scheme' });
const theme = createTheme({
  fontFamily: 'Manrope, system-ui, sans-serif',
  fontFamilyMonospace: '"DM Mono", ui-monospace, monospace',
  headings: { fontFamily: 'Manrope, system-ui, sans-serif', fontWeight: '700' },
  primaryColor: 'ink',
  defaultRadius: 0,
  colors: {
    ink: ['#f6f6f6', '#e7e7e7', '#cfcfcf', '#a7a7a7', '#7d7d7d', '#555555', '#363636', '#202020', '#171717', '#101010'],
    verify: ['#f6ffe5', '#eaffbd', '#dcff91', '#cdff66', '#b9ff38', '#9ee21f', '#7db514', '#5f8a0a', '#456604', '#315400']
  },
  components: {
    Button: { defaultProps: { radius: 0 } }, Paper: { defaultProps: { radius: 0, shadow: undefined } },
    Modal: { defaultProps: { radius: 0, overlayProps: { blur: 0 } } },
    Drawer: { defaultProps: { radius: 0, overlayProps: { blur: 0 } } },
    Input: { defaultProps: { radius: 0 } }, Badge: { defaultProps: { radius: 0 } }
  }
});

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 2_000, retry: 1, refetchOnWindowFocus: true } }
});
const params = new URLSearchParams(window.location.search);
const fixture = params.get('fixture') === 'docs';
const requestedFixtureClock = Number(params.get('fixture_now'));
const fixtureClock = Number.isFinite(requestedFixtureClock) && requestedFixtureClock > 0
  ? requestedFixtureClock : Date.now();
if (!window.location.hash && params.get('view')) {
  const id = params.get('id');
  window.location.hash = `/${params.get('view')}${id ? `/${id}` : ''}`;
}

createRoot(document.getElementById('local-root')!).render(
  <StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="auto" colorSchemeManager={colorSchemeManager}>
      <Notifications position="bottom-right" />
      <QueryClientProvider client={queryClient}>
        <Dashboard api={fixture ? createFixtureApi({ nowUnixMs: fixtureClock }) : localApi} fixture={fixture} />
      </QueryClientProvider>
    </MantineProvider>
  </StrictMode>
);
