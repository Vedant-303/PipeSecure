/**
 * PipeSecure — AI Engine Settings Persistence Store
 * Manages local browser persistence for engineMode ('static' | 'ai') and AI provider configuration.
 */

import { AI_PROVIDERS } from './universalAIClient.js';

const STORAGE_KEY = 'pipesecure_ai_config';

const defaultConfig = {
  engineMode: 'static', // 'static' | 'ai'
  provider: 'openai',    // 'openai' | 'anthropic' | 'gemini' | 'custom'
  apiKey: '',
  baseUrl: 'https://api.openai.com/v1',
  model: 'gpt-4o-mini',
};

/**
 * Load saved AI configuration from localStorage
 */
export function getAIConfig() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return defaultConfig;
    const parsed = JSON.parse(raw);
    const config = { ...defaultConfig, ...parsed };
    if (config.provider === 'gemini' && config.model === 'gemini-1.5-flash') {
      config.model = 'gemini-2.0-flash';
    }
    return config;
  } catch (err) {
    console.error('Error reading AI config from localStorage:', err);
    return defaultConfig;
  }
}

/**
 * Save AI configuration to localStorage
 */
export function saveAIConfig(config) {
  try {
    const current = getAIConfig();
    const updated = { ...current, ...config };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    return updated;
  } catch (err) {
    console.error('Error saving AI config to localStorage:', err);
    return config;
  }
}

/**
 * Reset AI configuration to default
 */
export function resetAIConfig() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch (err) {
    console.error('Error resetting AI config:', err);
  }
  return defaultConfig;
}
