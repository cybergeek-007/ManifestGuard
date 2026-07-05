import { useState, useEffect } from 'react';

// ── Types ────────────────────────────────────────────────────
export interface AIConfig {
  provider: string;
  apiKey: string;
  model: string;
  baseUrl: string;
  accountId?: string;
}

interface AIProvider {
  id: string;
  name: string;
  icon: string;
  defaultModel: string;
  models: string[];
  keyPlaceholder: string;
  docsUrl: string;
  needsAccountId?: boolean;
  free?: boolean;
}

// ── Provider presets ─────────────────────────────────────────
const PROVIDERS: AIProvider[] = [
  {
    id: 'groq', name: 'Groq', icon: '⚡', defaultModel: 'llama-3.3-70b-versatile',
    models: ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant', 'mixtral-8x7b-32768', 'gemma2-9b-it'],
    keyPlaceholder: 'gsk_...', docsUrl: 'https://console.groq.com/keys', free: true,
  },
  {
    id: 'gemini', name: 'Google Gemini', icon: '💎', defaultModel: 'gemini-2.0-flash',
    models: ['gemini-2.0-flash', 'gemini-2.5-flash', 'gemini-1.5-pro'],
    keyPlaceholder: 'AIza...', docsUrl: 'https://aistudio.google.com/apikey', free: true,
  },
  {
    id: 'openai', name: 'OpenAI', icon: '🤖', defaultModel: 'gpt-4o-mini',
    models: ['gpt-4o-mini', 'gpt-4o', 'gpt-4-turbo', 'gpt-3.5-turbo'],
    keyPlaceholder: 'sk-...', docsUrl: 'https://platform.openai.com/api-keys',
  },
  {
    id: 'openrouter', name: 'OpenRouter', icon: '🔀', defaultModel: 'meta-llama/llama-3.3-70b-instruct',
    models: ['meta-llama/llama-3.3-70b-instruct', 'anthropic/claude-sonnet-4-20250514', 'google/gemini-2.0-flash-001', 'mistralai/mistral-large-latest'],
    keyPlaceholder: 'sk-or-...', docsUrl: 'https://openrouter.ai/keys',
  },
  {
    id: 'together', name: 'Together AI', icon: '🤝', defaultModel: 'meta-llama/Llama-3.3-70B-Instruct-Turbo',
    models: ['meta-llama/Llama-3.3-70B-Instruct-Turbo', 'mistralai/Mixtral-8x22B-Instruct-v0.1', 'Qwen/Qwen2.5-72B-Instruct-Turbo'],
    keyPlaceholder: 'API key', docsUrl: 'https://api.together.xyz/settings/api-keys',
  },
  {
    id: 'mistral', name: 'Mistral AI', icon: '🌊', defaultModel: 'mistral-large-latest',
    models: ['mistral-large-latest', 'mistral-small-latest', 'codestral-latest', 'open-mistral-nemo'],
    keyPlaceholder: 'API key', docsUrl: 'https://console.mistral.ai/api-keys',
  },
  {
    id: 'deepseek', name: 'DeepSeek', icon: '🔍', defaultModel: 'deepseek-chat',
    models: ['deepseek-chat', 'deepseek-reasoner'],
    keyPlaceholder: 'sk-...', docsUrl: 'https://platform.deepseek.com/api_keys',
  },
  {
    id: 'huggingface', name: 'Hugging Face', icon: '🤗', defaultModel: 'meta-llama/Llama-3.3-70B-Instruct',
    models: ['meta-llama/Llama-3.3-70B-Instruct', 'mistralai/Mixtral-8x7B-Instruct-v0.1', 'Qwen/Qwen2.5-72B-Instruct'],
    keyPlaceholder: 'hf_...', docsUrl: 'https://huggingface.co/settings/tokens', free: true,
  },
  {
    id: 'xai', name: 'xAI (Grok)', icon: '𝕏', defaultModel: 'grok-3-mini-fast',
    models: ['grok-3-mini-fast', 'grok-3-fast', 'grok-2-latest'],
    keyPlaceholder: 'xai-...', docsUrl: 'https://console.x.ai',
  },
  {
    id: 'cerebras', name: 'Cerebras', icon: '🧠', defaultModel: 'llama-3.3-70b',
    models: ['llama-3.3-70b', 'llama-3.1-8b'],
    keyPlaceholder: 'API key', docsUrl: 'https://cloud.cerebras.ai', free: true,
  },
  {
    id: 'sambanova', name: 'SambaNova', icon: '🚀', defaultModel: 'Meta-Llama-3.3-70B-Instruct',
    models: ['Meta-Llama-3.3-70B-Instruct', 'DeepSeek-R1-Distill-Llama-70B'],
    keyPlaceholder: 'API key', docsUrl: 'https://cloud.sambanova.ai', free: true,
  },
  {
    id: 'cloudflare', name: 'Cloudflare Workers AI', icon: '☁️', defaultModel: '@cf/meta/llama-3.3-70b-instruct-fp8-fast',
    models: ['@cf/meta/llama-3.3-70b-instruct-fp8-fast', '@cf/meta/llama-3.1-8b-instruct', '@hf/mistral/mistral-7b-instruct-v0.2'],
    keyPlaceholder: 'API token', docsUrl: 'https://dash.cloudflare.com/profile/api-tokens',
    needsAccountId: true, free: true,
  },
  {
    id: 'custom', name: 'Custom Provider', icon: '🔧', defaultModel: '',
    models: [],
    keyPlaceholder: 'Your API key', docsUrl: '',
  },
];

const STORAGE_KEY = 'mg-ai-config';

// ── Public helpers ───────────────────────────────────────────
export function getAIConfig(): AIConfig | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const config = JSON.parse(raw) as AIConfig;
    if (!config.apiKey) return null;
    return config;
  } catch { return null; }
}

export function getAIHeaders(): Record<string, string> {
  const config = getAIConfig();
  if (!config || !config.apiKey) return {};
  const headers: Record<string, string> = {
    'X-AI-Provider': config.provider,
    'X-AI-Api-Key': config.apiKey,
    'X-AI-Model': config.model,
    'X-AI-Base-Url': config.baseUrl,
  };
  if (config.accountId) headers['X-AI-Account-Id'] = config.accountId;
  return headers;
}

// ── Component ────────────────────────────────────────────────
interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export default function AISettings({ isOpen, onClose }: Props) {
  const [selectedProvider, setSelectedProvider] = useState('groq');
  const [apiKey, setApiKey] = useState('');
  const [model, setModel] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [accountId, setAccountId] = useState('');
  const [customModel, setCustomModel] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [saved, setSaved] = useState(false);

  // Load saved config on open
  useEffect(() => {
    if (!isOpen) return;
    const config = getAIConfig();
    if (config) {
      setSelectedProvider(config.provider);
      setApiKey(config.apiKey);
      setModel(config.model);
      setBaseUrl(config.baseUrl);
      setAccountId(config.accountId || '');
      setSaved(true);
    }
  }, [isOpen]);

  const provider = PROVIDERS.find(p => p.id === selectedProvider) || PROVIDERS[0];

  function handleProviderSelect(id: string) {
    setSelectedProvider(id);
    const p = PROVIDERS.find(pr => pr.id === id);
    if (p) {
      setModel(p.defaultModel);
      setBaseUrl('');
      setAccountId('');
      setCustomModel('');
    }
    setTestResult(null);
    setSaved(false);
  }

  function handleSave() {
    const config: AIConfig = {
      provider: selectedProvider,
      apiKey,
      model: selectedProvider === 'custom' ? customModel : model,
      baseUrl,
      accountId: provider.needsAccountId ? accountId : undefined,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
    setSaved(true);
    setTestResult(null);
  }

  function handleClear() {
    localStorage.removeItem(STORAGE_KEY);
    setApiKey('');
    setModel(provider.defaultModel);
    setBaseUrl('');
    setAccountId('');
    setCustomModel('');
    setSaved(false);
    setTestResult(null);
  }

  async function handleTest() {
    setTesting(true);
    setTestResult(null);
    try {
      const API_BASE = import.meta.env.VITE_MANIFESTGUARD_API_URL ?? 'http://127.0.0.1:8000/api';
      const res = await fetch(`${API_BASE}/settings/ai/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: selectedProvider,
          apiKey,
          model: selectedProvider === 'custom' ? customModel : model,
          baseUrl,
          accountId,
        }),
      });
      const data = await res.json();
      setTestResult(data);
    } catch {
      setTestResult({ success: false, message: 'Could not reach the backend server.' });
    } finally {
      setTesting(false);
    }
  }

  if (!isOpen) return null;

  const currentConfig = getAIConfig();
  const statusText = currentConfig
    ? `Using: ${PROVIDERS.find(p => p.id === currentConfig.provider)?.name || currentConfig.provider} (${currentConfig.model})`
    : 'No AI provider configured';

  return (
    <div className="ai-settings-overlay" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="ai-settings-modal" role="dialog" aria-label="AI Provider Settings">
        {/* Header */}
        <div className="ai-settings-header">
          <div>
            <h2>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ verticalAlign: 'middle', marginRight: 8 }}>
                <circle cx="12" cy="12" r="3" /><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
              </svg>
              AI Provider Settings
            </h2>
            <p className="ai-status">{statusText}</p>
          </div>
          <button className="ai-close-btn" onClick={onClose} aria-label="Close settings">&times;</button>
        </div>

        {/* Provider Grid */}
        <div className="ai-provider-grid">
          {PROVIDERS.map(p => (
            <button
              key={p.id}
              className={`ai-provider-card${selectedProvider === p.id ? ' selected' : ''}`}
              onClick={() => handleProviderSelect(p.id)}
              aria-pressed={selectedProvider === p.id}
            >
              <span className="provider-icon">{p.icon}</span>
              <span className="provider-name">{p.name}</span>
              {p.free && <span className="free-badge">Free</span>}
            </button>
          ))}
        </div>

        {/* Form */}
        <div className="ai-settings-form">
          {/* API Key */}
          <label className="ai-field-label">
            API Key
            {provider.docsUrl && (
              <a href={provider.docsUrl} target="_blank" rel="noopener noreferrer" className="ai-docs-link">
                Get your API key →
              </a>
            )}
          </label>
          <div className="ai-key-input-wrapper">
            <input
              type={showKey ? 'text' : 'password'}
              value={apiKey}
              onChange={e => { setApiKey(e.target.value); setSaved(false); setTestResult(null); }}
              placeholder={provider.keyPlaceholder}
              className="ai-input"
              autoComplete="off"
              spellCheck={false}
            />
            <button
              type="button"
              className="ai-key-toggle"
              onClick={() => setShowKey(!showKey)}
              aria-label={showKey ? 'Hide API key' : 'Show API key'}
            >
              {showKey ? '🙈' : '👁️'}
            </button>
          </div>

          {/* Model Selection */}
          {selectedProvider !== 'custom' ? (
            <>
              <label className="ai-field-label">Model</label>
              <select
                value={model}
                onChange={e => { setModel(e.target.value); setSaved(false); }}
                className="ai-input ai-select"
              >
                {provider.models.map(m => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
            </>
          ) : (
            <>
              <label className="ai-field-label">Base URL (OpenAI-compatible endpoint)</label>
              <input
                type="url"
                value={baseUrl}
                onChange={e => { setBaseUrl(e.target.value); setSaved(false); }}
                placeholder="https://your-api.com/v1"
                className="ai-input"
              />
              <label className="ai-field-label">Model Name</label>
              <input
                type="text"
                value={customModel}
                onChange={e => { setCustomModel(e.target.value); setSaved(false); }}
                placeholder="e.g. llama-3.3-70b"
                className="ai-input"
              />
            </>
          )}

          {/* Cloudflare Account ID */}
          {provider.needsAccountId && (
            <>
              <label className="ai-field-label">Cloudflare Account ID</label>
              <input
                type="text"
                value={accountId}
                onChange={e => { setAccountId(e.target.value); setSaved(false); }}
                placeholder="Your account ID from the Cloudflare dashboard URL"
                className="ai-input"
              />
            </>
          )}

          {/* Test Result */}
          {testResult && (
            <div className={`ai-test-result ${testResult.success ? 'success' : 'error'}`}>
              {testResult.success ? '✅' : '❌'} {testResult.message}
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="ai-settings-actions">
          <button
            className="ai-btn ai-btn-test"
            onClick={handleTest}
            disabled={!apiKey || testing}
          >
            {testing ? (
              <><span className="ai-spinner" /> Testing...</>
            ) : (
              '🔌 Test Connection'
            )}
          </button>
          <div className="ai-actions-right">
            <button className="ai-btn ai-btn-clear" onClick={handleClear}>
              Clear
            </button>
            <button
              className="ai-btn ai-btn-save"
              onClick={handleSave}
              disabled={!apiKey}
            >
              {saved ? '✓ Saved' : 'Save'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
