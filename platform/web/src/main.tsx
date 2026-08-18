import { createRoot } from 'react-dom/client';
import { App } from './site/SiteApp';

const applicationRoot = document.getElementById('root');
if (applicationRoot) createRoot(applicationRoot).render(<App />);
