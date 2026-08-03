/*
 * PII Guard UI behaviour.
 *
 * Extracted from an inline <script> so the Content-Security-Policy can specify
 * script-src 'self' with no 'unsafe-inline'. That is not tidiness: 'unsafe-inline'
 * defeats the main thing CSP is for, because an injected <script> block executes
 * under exactly the same permission as the page's own.
 *
 * Every value that originates from the server is written with textContent or
 * createTextNode, never innerHTML. The model's output is untrusted text — it is
 * influenced by whatever the user typed — and assigning it to innerHTML would turn
 * "ask the model to emit an <img onerror=...> tag" into stored XSS in the one page
 * that also holds the admin key.
 */

(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);

  const els = {
    prompt: $('promptInput'),
    noise: $('noiseToggle'),
    sendBtn: $('sendBtn'),
    sendText: $('sendText'),
    spinner: $('spinner'),
    attackBtn: $('attackBtn'),
    adminKey: $('adminKey'),
    response: $('llmResponse'),
    warnings: $('warnings'),
    original: $('originalPrompt'),
    sanitized: $('sanitizedPrompt'),
    redactionSummary: $('redactionSummary'),
    attackLog: $('attackLog'),
    attackEmpty: $('attackEmpty'),
    suiteSummary: $('suiteSummary'),
    metaRow: $('metaRow'),
    sessionId: $('sessionId'),
    statusDot: $('statusDot'),
    statusText: $('statusText'),
    tags: $('topbarTags')
  };

  const TOKEN_RE = /(\[[A-Z]+_[A-Z]{8,32}\])/g;

  // ── helpers ──────────────────────────────────────────────────────────────

  function setText(el, text, className) {
    el.textContent = text == null ? '' : String(text);
    if (className !== undefined) {
      el.className = className;
    }
  }

  function clear(el) {
    while (el.firstChild) {
      el.removeChild(el.firstChild);
    }
  }

  function tag(text, kind) {
    const span = document.createElement('span');
    span.className = 'tag tag-' + kind;
    span.textContent = text;
    return span;
  }

  /** Renders text with placeholders highlighted, using text nodes throughout. */
  function renderWithTokens(el, text) {
    clear(el);
    if (!text) {
      el.textContent = '—';
      return;
    }
    text.split(TOKEN_RE).forEach((part) => {
      if (!part) return;
      if (/^\[[A-Z]+_[A-Z]{8,32}\]$/.test(part)) {
        const span = document.createElement('span');
        span.className = 'token-highlight';
        span.textContent = part;
        el.appendChild(span);
      } else {
        el.appendChild(document.createTextNode(part));
      }
    });
  }

  function renderWarnings(warnings) {
    clear(els.warnings);
    (warnings || []).forEach((message) => {
      const div = document.createElement('div');
      div.className = 'warning';
      div.textContent = message;
      els.warnings.appendChild(div);
    });
  }

  function renderRedactionSummary(counts) {
    clear(els.redactionSummary);
    const entries = Object.entries(counts || {});
    if (!entries.length) {
      const span = document.createElement('span');
      span.className = 'tag tag-blue';
      span.textContent = 'no sensitive values detected';
      els.redactionSummary.appendChild(span);
      return;
    }
    entries.forEach(([type, count]) => {
      els.redactionSummary.appendChild(tag(type + ' × ' + count, 'green'));
    });
  }

  /** Reads an error message from a JSON body without ever trusting it as markup. */
  async function readError(res) {
    try {
      const body = await res.json();
      return body.error || body.llmResponse || ('HTTP ' + res.status);
    } catch (e) {
      return 'HTTP ' + res.status;
    }
  }

  // ── proxy ────────────────────────────────────────────────────────────────

  async function sendPrompt() {
    const prompt = els.prompt.value.trim();
    if (!prompt) return;

    els.sendBtn.disabled = true;
    els.spinner.classList.add('active');
    els.sendText.textContent = 'Processing…';

    setText(els.response, 'Redacting  →  perturbing numbers  →  forwarding to the model…',
            'response-output');
    renderWarnings([]);

    // The "before" pane shows what the user typed, taken from the textarea. The server
    // no longer echoes the raw prompt back in the response — it already left the browser
    // once and there is no reason for it to make the return trip.
    setText(els.original, prompt);

    try {
      const res = await fetch('/api/proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: prompt, applyNoise: els.noise.checked })
      });

      const data = await res.json().catch(() => null);

      if (!data) {
        setText(els.response, 'HTTP ' + res.status, 'response-output error');
        return;
      }

      if (res.status === 429) {
        setText(els.response, data.error || 'Rate limit exceeded. Please wait a minute.',
                'response-output error');
        return;
      }

      if (data.attackDetected) {
        setText(els.response,
                data.llmResponse + '\n\nDetected by: ' + data.detectionMethod +
                '\nRule: ' + data.detectionRule,
                'response-output error');
        renderWithTokens(els.sanitized, null);
        renderRedactionSummary({});
        showSession(data.sessionId);
        return;
      }

      setText(els.response, data.llmResponse,
              res.ok ? 'response-output ok' : 'response-output error');
      renderWithTokens(els.sanitized, data.sanitizedPrompt);
      renderRedactionSummary(data.piiRedacted);
      renderWarnings(data.warnings);
      showSession(data.sessionId);

    } catch (e) {
      setText(els.response, 'Network error: ' + e.message, 'response-output error');
    } finally {
      els.sendBtn.disabled = false;
      els.spinner.classList.remove('active');
      els.sendText.textContent = 'Send to proxy';
    }
  }

  function showSession(sessionId) {
    if (!sessionId) return;
    els.metaRow.hidden = false;
    els.sessionId.textContent = sessionId.substring(0, 18) + '…';
  }

  // ── detection suite ──────────────────────────────────────────────────────

  async function runSuite() {
    const key = els.adminKey.value.trim();
    if (!key) {
      els.attackEmpty.hidden = false;
      setText(els.attackEmpty, 'The detection suite is an admin endpoint. Enter the admin key.',
              'empty-state');
      return;
    }

    els.attackBtn.disabled = true;
    els.attackBtn.textContent = 'Running…';
    els.attackEmpty.hidden = true;
    clear(els.attackLog);
    clear(els.suiteSummary);

    try {
      const res = await fetch('/api/attack', { headers: { 'X-Admin-Key': key } });

      if (!res.ok) {
        els.attackEmpty.hidden = false;
        setText(els.attackEmpty,
                res.status === 403 || res.status === 401
                  ? 'Rejected: invalid admin key.'
                  : await readError(res),
                'empty-state');
        return;
      }

      const data = await res.json();

      const summary = document.createElement('div');
      summary.className = 'suite-summary ' + (data.failed === 0 ? 'pass' : 'fail');
      summary.textContent = data.passed + ' / ' + data.total + ' passed'
                          + (data.failed ? '  —  ' + data.failed + ' FAILED' : '');
      els.suiteSummary.appendChild(summary);

      for (const row of data.results) {
        await new Promise((r) => setTimeout(r, 120));
        els.attackLog.appendChild(buildRow(row));
      }

    } catch (e) {
      els.attackEmpty.hidden = false;
      setText(els.attackEmpty, 'Error: ' + e.message, 'empty-state');
    } finally {
      els.attackBtn.disabled = false;
      els.attackBtn.textContent = 'Run detection suite';
    }
  }

  function buildRow(row) {
    const entry = document.createElement('div');
    entry.className = 'attack-entry' + (row.passed ? '' : ' failed');

    const isControl = String(row.attackType).startsWith('CONTROL');

    const type = document.createElement('span');
    type.className = 'attack-type' + (isControl ? ' control' : '');
    type.textContent = row.attackType;

    const payload = document.createElement('span');
    payload.className = 'attack-payload';
    payload.title = row.payload;
    payload.textContent = row.payload;

    const result = document.createElement('span');
    result.className = 'result-pill ' + (row.passed ? 'pass' : 'fail');
    result.textContent = row.blocked
      ? 'BLOCKED · ' + row.detectionMethod
      : 'ALLOWED';
    result.title = row.status + (row.rule ? ' (' + row.rule + ')' : '');

    entry.appendChild(type);
    entry.appendChild(payload);
    entry.appendChild(result);

    requestAnimationFrame(() => requestAnimationFrame(() => entry.classList.add('visible')));
    return entry;
  }

  // ── status ───────────────────────────────────────────────────────────────

  async function refreshStatus() {
    clear(els.tags);
    try {
      const res = await fetch('/api/health');
      const data = await res.json();

      const degraded = !data.llmConfigured || !data.nerModelLoaded || !data.mlServiceAvailable;
      els.statusDot.className = 'status-dot ' + (data.llmConfigured ? (degraded ? 'warn' : 'up') : 'down');
      els.statusText.textContent = degraded ? 'running — degraded' : 'running';

      els.tags.appendChild(tag(data.llmConfigured ? 'LLM configured' : 'LLM not configured',
                               data.llmConfigured ? 'green' : 'red'));
      els.tags.appendChild(tag(data.nerModelLoaded ? 'NER active' : 'NER unavailable',
                               data.nerModelLoaded ? 'green' : 'amber'));
      els.tags.appendChild(tag(data.mlServiceAvailable ? 'ML classifier up' : 'ML classifier down',
                               data.mlServiceAvailable ? 'green' : 'amber'));
      els.tags.appendChild(tag('regex rules always on', 'blue'));

    } catch (e) {
      els.statusDot.className = 'status-dot down';
      els.statusText.textContent = 'unreachable';
    }
  }

  // ── wiring ───────────────────────────────────────────────────────────────

  els.sendBtn.addEventListener('click', sendPrompt);
  els.attackBtn.addEventListener('click', runSuite);
  els.prompt.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'Enter') sendPrompt();
  });

  refreshStatus();
  setInterval(refreshStatus, 30000);
})();
