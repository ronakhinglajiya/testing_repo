'use strict';

/**
 * Send one short WAV chunk to Sarvam speech-to-text.
 * Docs: POST {baseUrl}/speech-to-text, multipart form, header `api-subscription-key`.
 * Returns { text, language }.
 */
async function transcribeWithSarvam(wav, cfg) {
  const form = new FormData();
  form.append('file', new Blob([wav], { type: 'audio/wav' }), 'chunk.wav');
  form.append('model', cfg.model);
  // `mode` only exists on the Saaras family (transcribe | translate | codemix ...)
  if (cfg.mode && /^saaras/i.test(cfg.model)) form.append('mode', cfg.mode);
  if (cfg.language) form.append('language_code', cfg.language);

  const res = await fetch(`${cfg.baseUrl}/speech-to-text`, {
    method: 'POST',
    headers: { 'api-subscription-key': cfg.apiKey },
    body: form,
    signal: AbortSignal.timeout(cfg.timeoutMs || 20000)
  });

  const raw = await res.text();
  let json = null;
  try { json = JSON.parse(raw); } catch { /* non-JSON error body */ }

  if (!res.ok) {
    const detail = (json && (json.error?.message || json.message || json.detail)) || raw.slice(0, 200);
    const err = new Error(`Sarvam speech-to-text failed (${res.status}): ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`);
    err.status = res.status === 401 || res.status === 403 ? 401 : 502;
    throw err;
  }

  return {
    text: String(json?.transcript || '').trim(),
    language: json?.language_code || null
  };
}

module.exports = { transcribeWithSarvam };
