import {
  siAnthropic,
  siGooglegemini,
  siX,
} from 'simple-icons';

// OpenAI removed its mark from Simple Icons; retain the official monochrome knot path.
const OPENAI_PATH = 'M22.28 9.82a5.99 5.99 0 0 0-.52-4.91 6.05 6.05 0 0 0-6.51-2.9A6.06 6.06 0 0 0 4.98 4.18a5.99 5.99 0 0 0-4 2.9 6.05 6.05 0 0 0 .74 7.1 5.98 5.98 0 0 0 .51 4.91 6.05 6.05 0 0 0 6.52 2.9A5.98 5.98 0 0 0 13.26 24a6.06 6.06 0 0 0 5.77-4.21 5.99 5.99 0 0 0 4-2.9 6.06 6.06 0 0 0-.75-7.07zM13.26 22.43a4.48 4.48 0 0 1-2.88-1.04l.14-.08 4.78-2.76a.8.8 0 0 0 .39-.68v-6.74l2.02 1.17a.07.07 0 0 1 .04.05v5.58a4.5 4.5 0 0 1-4.49 4.5zM3.6 18.3a4.47 4.47 0 0 1-.54-3.01l.15.08 4.78 2.76a.77.77 0 0 0 .78 0l5.84-3.37v2.33a.08.08 0 0 1-.03.06L9.74 19.95A4.5 4.5 0 0 1 3.6 18.3zM2.34 7.9a4.49 4.49 0 0 1 2.37-1.97v5.67a.77.77 0 0 0 .39.68l5.81 3.35-2.02 1.17a.08.08 0 0 1-.07 0l-4.83-2.79A4.5 4.5 0 0 1 2.34 7.87zm16.6 3.86-5.83-3.39 2.02-1.16a.08.08 0 0 1 .07 0l4.83 2.79a4.49 4.49 0 0 1-.68 8.1v-5.67a.79.79 0 0 0-.41-.67zm2.01-3.02-.14-.09-4.77-2.78a.78.78 0 0 0-.79 0L9.41 9.23V6.9a.07.07 0 0 1 .03-.06l4.83-2.79a4.5 4.5 0 0 1 6.68 4.66zm-12.64 4.13-2.02-1.16a.08.08 0 0 1-.04-.06V6.08a4.5 4.5 0 0 1 7.38-3.45l-.14.08-4.78 2.76a.8.8 0 0 0-.39.68zm1.1-2.36 2.6-1.5 2.61 1.5v3l-2.6 1.5-2.61-1.5z';

export const PREMIER_COLORS = {
  accent: '#6F7BF7',
  accentStrong: '#9EAAFF',
  accentDeep: '#4F5BD5',
  ink: '#05060A',
  panel: '#0B0D14',
  text: '#F7F8FC',
  muted: '#98A2B5',
  success: '#63DCA5',
  warning: '#F5BC68',
  danger: '#FF7C78',
} as const;

export type ProviderMarkId = 'anthropic' | 'openai' | 'google' | 'xai' | 'terminal';

export type ProviderMark = {
  id: ProviderMarkId;
  label: string;
  path: string;
  hex: string;
  viewBox: string;
};

export const PROVIDER_MARKS: Record<ProviderMarkId, ProviderMark> = {
  anthropic: {
    id: 'anthropic',
    label: 'Claude',
    path: siAnthropic.path,
    hex: `#${siAnthropic.hex}`,
    viewBox: '0 0 24 24',
  },
  openai: {
    id: 'openai',
    label: 'Codex',
    path: OPENAI_PATH,
    hex: '#FFFFFF',
    viewBox: '0 0 24 24',
  },
  google: {
    id: 'google',
    label: 'Gemini',
    path: siGooglegemini.path,
    hex: `#${siGooglegemini.hex}`,
    viewBox: '0 0 24 24',
  },
  xai: {
    id: 'xai',
    label: 'Grok',
    path: siX.path,
    hex: `#${siX.hex}`,
    viewBox: '0 0 24 24',
  },
  terminal: {
    id: 'terminal',
    label: 'Any CLI',
    path: 'M4 5.5 10.5 12 4 18.5M12.5 18.5H20',
    hex: PREMIER_COLORS.accentStrong,
    viewBox: '0 0 24 24',
  },
};
