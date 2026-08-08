/**
 * PipeSecure — Universal Multi-Provider AI Client
 *
 * Supports OpenAI, Anthropic Claude, Google Gemini, and Custom OpenAI-compatible endpoints
 * (e.g. Ollama http://localhost:11434/v1, DeepSeek, Groq, LM Studio, vLLM, Together AI).
 */

/**
 * Default configurations per AI provider
 */
export const AI_PROVIDERS = {
  openai: {
    id: 'openai',
    name: 'OpenAI',
    defaultBaseUrl: 'https://api.openai.com/v1',
    defaultModel: 'gpt-4o-mini',
    models: ['gpt-4o-mini', 'gpt-4o', 'gpt-3.5-turbo'],
    placeholderKey: 'sk-proj-...',
  },
  anthropic: {
    id: 'anthropic',
    name: 'Anthropic Claude',
    defaultBaseUrl: 'https://api.anthropic.com/v1',
    defaultModel: 'claude-3-5-sonnet-20240620',
    models: ['claude-3-5-sonnet-20240620', 'claude-3-haiku-20240307'],
    placeholderKey: 'sk-ant-...',
  },
  gemini: {
    id: 'gemini',
    name: 'Google Gemini',
    defaultBaseUrl: 'https://generativelanguage.googleapis.com/v1beta',
    defaultModel: 'gemini-2.0-flash',
    models: ['gemini-2.0-flash', 'gemini-1.5-flash-latest', 'gemini-1.5-pro'],
    placeholderKey: 'AIzaSy...',
  },
  custom: {
    id: 'custom',
    name: 'Custom / Local LLM (Ollama, DeepSeek, Groq)',
    defaultBaseUrl: 'http://localhost:11434/v1',
    defaultModel: 'llama3',
    models: ['llama3', 'deepseek-coder', 'mixtral-8x7b', 'custom'],
    placeholderKey: 'Optional API Key or leave blank for local Ollama',
  },
};

/**
 * Dynamically fetch available live models directly from provider API endpoints
 */
export async function fetchAvailableModels({ provider, apiKey, baseUrl }) {
  const pDef = AI_PROVIDERS[provider] || AI_PROVIDERS.openai;
  const fallbackModels = pDef.models || [pDef.defaultModel];

  try {
    if (provider === 'openai') {
      if (!apiKey) return fallbackModels;
      const res = await fetch('https://api.openai.com/v1/models', {
        headers: { Authorization: `Bearer ${apiKey}` },
      });
      if (!res.ok) return fallbackModels;
      const data = await res.json();
      const gptModels = (data.data || [])
        .map(m => m.id)
        .filter(id => (id.startsWith('gpt-') || id.startsWith('o1') || id.startsWith('o3')) && !id.includes('realtime') && !id.includes('audio') && !id.includes('instruct'));
      gptModels.sort();
      return gptModels.length > 0 ? gptModels : fallbackModels;
    }

    if (provider === 'gemini') {
      if (!apiKey) return fallbackModels;
      const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`);
      if (!res.ok) return fallbackModels;
      const data = await res.json();
      const geminiModels = (data.models || [])
        .filter(m => m.supportedGenerationMethods?.includes('generateContent'))
        .map(m => m.name.replace(/^models\//, ''))
        .filter(id => id.startsWith('gemini-'));
      return geminiModels.length > 0 ? geminiModels : fallbackModels;
    }

    if (provider === 'anthropic') {
      if (!apiKey) return fallbackModels;
      const res = await fetch('https://api.anthropic.com/v1/models', {
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
      });
      if (!res.ok) return fallbackModels;
      const data = await res.json();
      const claudeModels = (data.data || []).map(m => m.id);
      return claudeModels.length > 0 ? claudeModels : fallbackModels;
    }

    if (provider === 'custom') {
      const url = `${(baseUrl || pDef.defaultBaseUrl).replace(/\/$/, '')}/models`;
      const headers = apiKey ? { Authorization: `Bearer ${apiKey}` } : {};
      const res = await fetch(url, { headers });
      if (!res.ok) return fallbackModels;
      const data = await res.json();
      const customModels = (data.data || data.models || [])
        .map(m => (typeof m === 'string' ? m : m.id || m.name))
        .filter(Boolean);
      return customModels.length > 0 ? customModels : fallbackModels;
    }
  } catch (err) {
    console.warn(`Dynamic model fetch warning for ${provider}:`, err);
  }

  return fallbackModels;
}

const delay = (ms) => new Promise(res => setTimeout(res, ms));

/**
 * Retry helper with exponential backoff for rate limits (429)
 */
async function callWithRetry(fn, maxRetries = 2, baseDelayMs = 2000) {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      const is429 = err.message && (err.message.includes('429') || err.message.toLowerCase().includes('quota'));
      if (is429 && attempt < maxRetries) {
        const waitTime = baseDelayMs * (attempt + 1);
        console.warn(`Rate limit (429) encountered. Waiting ${waitTime / 1000}s before retry ${attempt + 1}/${maxRetries}...`);
        await delay(waitTime);
        continue;
      }
      throw err;
    }
  }
}

/**
 * Format security findings and code context into a structured prompt for AI
 */
function buildAnalysisPrompt(fileContent, findings, filePath) {
  const findingsSummary = findings.map(f => `- Line ${f.line}: ${f.title} (${f.category}, Severity: ${f.severity})`).join('\n');

  return `You are an expert Data DevSecOps and Pipeline Security Analyst.
Review the following data pipeline file "${filePath}" and its static security findings.

STATIC FINDINGS DETECTED:
${findingsSummary}

FILE CONTENT:
\`\`\`
${fileContent}
\`\`\`

Provide your response in JSON format with the following exact structure:
{
  "aiImpact": "Detailed 2-3 sentence architectural risk analysis explaining why these findings compromise the data pipeline.",
  "aiConfidence": 95,
  "remediatedCode": "Complete refactored, secure version of the code resolving all security findings while maintaining exact pipeline functionality."
}`;
}

/**
 * Helper to extract clean human-readable error messages from API responses
 */
function parseHumanErrorMessage(providerName, status, errorText) {
  try {
    const json = JSON.parse(errorText);
    const msg = json.error?.message || json.message || (typeof json.error === 'string' ? json.error : null);
    if (msg) {
      if (status === 429 || errorText.includes('429') || msg.toLowerCase().includes('quota')) {
        return `${providerName} Quota Exceeded (429): ${msg}`;
      }
      if (status === 400 || status === 401 || status === 403) {
        return `${providerName} Auth Error (${status}): ${msg}`;
      }
      return `${providerName} Error (${status}): ${msg}`;
    }
  } catch (e) {
    // fallback if non-JSON response
  }
  return `${providerName} Error (${status}): ${errorText.substring(0, 160)}`;
}

/**
 * Call OpenAI or OpenAI-Compatible API endpoint (Ollama, DeepSeek, Groq, LM Studio)
 */
async function callOpenAICompatible({ baseUrl, apiKey, model, prompt }) {
  const endpoint = `${baseUrl.replace(/\/$/, '')}/chat/completions`;
  const headers = {
    'Content-Type': 'application/json',
  };
  if (apiKey) {
    headers['Authorization'] = `Bearer ${apiKey}`;
  }

  const response = await fetch(endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model: model || 'gpt-4o-mini',
      messages: [
        { role: 'system', content: 'You are a JSON-only response security assistant.' },
        { role: 'user', content: prompt }
      ],
      temperature: 0.2,
      response_format: { type: 'json_object' }
    })
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(parseHumanErrorMessage('OpenAI API', response.status, errorText));
  }

  const data = await response.json();
  const text = data.choices?.[0]?.message?.content || '{}';
  return JSON.parse(text);
}

/**
 * Call Anthropic API endpoint
 */
async function callAnthropic({ apiKey, model, prompt }) {
  const endpoint = 'https://api.anthropic.com/v1/messages';
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: model || 'claude-3-5-sonnet-20240620',
      max_tokens: 1500,
      messages: [{ role: 'user', content: prompt }],
    })
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(parseHumanErrorMessage('Anthropic API', response.status, errorText));
  }

  const data = await response.json();
  const text = data.content?.[0]?.text || '{}';
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  return JSON.parse(jsonMatch ? jsonMatch[0] : text);
}

/**
 * Call Google Gemini API endpoint with model fallback
 */
async function callGemini({ apiKey, model, prompt }) {
  // Always prioritize gemini-2.0-flash to avoid 404 on legacy aliases
  const targetModel = (model && model !== 'gemini-1.5-flash') ? model : 'gemini-2.0-flash';
  const candidateModels = [
    targetModel,
    'gemini-2.0-flash',
    'gemini-1.5-flash-latest',
    'gemini-1.5-pro'
  ];

  const modelsToTry = [...new Set(candidateModels)];
  let lastError = null;

  for (const mName of modelsToTry) {
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${mName}:generateContent?key=${apiKey}`;
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { responseMimeType: 'application/json' }
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        const formattedErr = parseHumanErrorMessage('Gemini API', response.status, errorText);
        if (response.status === 404) {
          lastError = new Error(formattedErr);
          continue;
        }
        throw new Error(formattedErr);
      }

      const data = await response.json();
      const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '{}';
      return JSON.parse(text);
    } catch (err) {
      if (err.message && err.message.includes('404')) {
        lastError = err;
        continue;
      }
      throw err;
    }
  }

  throw lastError || new Error('Gemini API Error: No compatible Gemini model endpoint found for this key.');
}

/**
 * Test AI Provider Connectivity with provided API key and configuration
 */
export async function testAIConnection({ provider, apiKey, baseUrl, model }) {
  try {
    const prompt = 'Respond with JSON: {"status": "ok"}';
    const effectiveBaseUrl = baseUrl || AI_PROVIDERS[provider]?.defaultBaseUrl;
    const effectiveModel = (provider === 'gemini' && model === 'gemini-1.5-flash') ? 'gemini-2.0-flash' : (model || AI_PROVIDERS[provider]?.defaultModel);

    if (provider === 'anthropic') {
      await callWithRetry(() => callAnthropic({ apiKey, model: effectiveModel, prompt }));
    } else if (provider === 'gemini') {
      await callWithRetry(() => callGemini({ apiKey, model: effectiveModel, prompt }));
    } else {
      await callWithRetry(() => callOpenAICompatible({ baseUrl: effectiveBaseUrl, apiKey, model: effectiveModel, prompt }));
    }
    return { success: true, message: 'AI Connection Successful!' };
  } catch (err) {
    return { success: false, message: err.message || 'AI Connection Failed' };
  }
}

/**
 * Enrich static findings with Universal AI provider analysis
 */
export async function enrichFindingsWithAI(files, staticFindings, aiConfig) {
  const { provider, apiKey, baseUrl, model } = aiConfig;
  if (!provider) return staticFindings;

  const effectiveBaseUrl = baseUrl || AI_PROVIDERS[provider]?.defaultBaseUrl;
  const effectiveModel = (provider === 'gemini' && model === 'gemini-1.5-flash') ? 'gemini-2.0-flash' : (model || AI_PROVIDERS[provider]?.defaultModel);

  const enrichedFindings = [...staticFindings];
  const fileMap = new Map(files.map(f => [f.path, f]));

  // Group findings by file to minimize API calls
  const findingsByFile = {};
  for (const finding of staticFindings) {
    if (!findingsByFile[finding.filePath]) {
      findingsByFile[finding.filePath] = [];
    }
    findingsByFile[finding.filePath].push(finding);
  }

  const entries = Object.entries(findingsByFile);
  for (let idx = 0; idx < entries.length; idx++) {
    const [filePath, fileFindings] = entries[idx];
    const file = fileMap.get(filePath);
    if (!file || !file.content) continue;

    // Rate-limit throttle delay between requests (1.2s per file) for free-tier APIs like Gemini
    if (idx > 0) {
      await delay(1200);
    }

    try {
      const prompt = buildAnalysisPrompt(file.content, fileFindings, filePath);
      let result = {};

      const execCall = async () => {
        if (provider === 'anthropic') {
          return await callAnthropic({ apiKey, model: effectiveModel, prompt });
        } else if (provider === 'gemini') {
          return await callGemini({ apiKey, model: effectiveModel, prompt });
        } else {
          return await callOpenAICompatible({ baseUrl: effectiveBaseUrl, apiKey, model: effectiveModel, prompt });
        }
      };

      result = await callWithRetry(execCall, 2, 2000);

      // Enrich findings for this file
      for (const finding of enrichedFindings) {
        if (finding.filePath === filePath) {
          finding.aiImpact = result.aiImpact || finding.whyItMatters;
          finding.aiConfidence = result.aiConfidence || 95;
          if (result.remediatedCode) {
            finding.aiRemediatedCode = result.remediatedCode;
          }
        }
      }
    } catch (err) {
      console.warn(`AI Analysis warning for ${filePath}:`, err);
    }
  }

  return enrichedFindings;
}
