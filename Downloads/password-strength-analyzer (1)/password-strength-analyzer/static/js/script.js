(function () {
  const input = document.getElementById('password-input');
  const toggleBtn = document.getElementById('toggle-visibility');
  const eyeOpen = document.getElementById('eye-open');
  const eyeClosed = document.getElementById('eye-closed');
  const generateBtn = document.getElementById('generate-btn');

  const dialFill = document.getElementById('dial-fill');
  const dialNeedle = document.getElementById('dial-needle');
  const dialScore = document.getElementById('dial-score');
  const dialLabel = document.getElementById('dial-label');

  const statLength = document.getElementById('stat-length');
  const statEntropy = document.getElementById('stat-entropy');
  const statCrack = document.getElementById('stat-crack');

  const checklist = document.getElementById('checklist');
  const findingsBox = document.getElementById('findings');
  const findingsList = document.getElementById('findings-list');
  const suggestionsList = document.getElementById('suggestions-list');

  const STRENGTH_COLORS = {
    empty: '#2a323e',
    weak: '#e0563f',
    medium: '#e0a53f',
    strong: '#3fd68c',
  };

  let debounceTimer = null;

  // --- visibility toggle ---
  toggleBtn.addEventListener('click', () => {
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    eyeOpen.style.display = isPassword ? 'none' : 'block';
    eyeClosed.style.display = isPassword ? 'block' : 'none';
    toggleBtn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    input.focus();
  });

  // --- crack time estimate (client-side, from entropy bits) ---
  function formatCrackTime(entropyBits) {
    if (!entropyBits) return '—';
    const guesses = Math.pow(2, entropyBits);
    const guessesPerSecond = 1e10; // assume a fast offline attack
    let seconds = guesses / guessesPerSecond / 2;

    const units = [
      ['year', 31536000],
      ['day', 86400],
      ['hour', 3600],
      ['minute', 60],
      ['second', 1],
    ];

    if (seconds < 1) return 'instantly';
    if (seconds > 31536000 * 1000) return 'centuries';

    for (const [name, secs] of units) {
      if (seconds >= secs) {
        const value = Math.round(seconds / secs);
        return `~${value.toLocaleString()} ${name}${value !== 1 ? 's' : ''}`;
      }
    }
    return '—';
  }

  // --- render analysis result into the UI ---
  function renderResult(result) {
    const score = result.length === 0 ? 0 : result.score;
    const label = result.label;

    // dial fill (semicircle, pathLength=100 so dasharray directly = percent)
    dialFill.setAttribute('stroke-dasharray', `${score} 100`);
    dialFill.style.stroke = STRENGTH_COLORS[label] || STRENGTH_COLORS.empty;

    // needle: -90deg (score 0) to +90deg (score 100)
    const angle = (score / 100) * 180 - 90;
    dialNeedle.style.transform = `rotate(${angle}deg)`;

    dialScore.textContent = result.length === 0 ? '--' : score;
    dialScore.style.color = STRENGTH_COLORS[label] || '#e7ecf3';
    dialLabel.textContent = result.length === 0 ? 'enter a password' : label;

    statLength.textContent = result.length;
    statEntropy.innerHTML = `${result.entropy_bits.toFixed(1)} <small>bits</small>`;
    statCrack.textContent = formatCrackTime(result.entropy_bits);

    // checklist
    checklist.querySelectorAll('.check-item').forEach((item) => {
      const key = item.dataset.key;
      const met = !!result.checks[key];
      item.classList.toggle('met', met);
    });

    // findings (patterns + common password)
    const findings = [...result.patterns_found];
    if (result.is_common_password) {
      findings.push('This password (or a close variant) is on a known common-password list');
    }
    if (findings.length) {
      findingsBox.hidden = false;
      findingsList.innerHTML = findings.map((f) => `<li>${escapeHtml(f)}</li>`).join('');
    } else {
      findingsBox.hidden = true;
      findingsList.innerHTML = '';
    }

    // suggestions
    if (result.suggestions && result.suggestions.length) {
      suggestionsList.innerHTML = result.suggestions
        .map((s) => `<li>${escapeHtml(s)}</li>`)
        .join('');
    } else {
      suggestionsList.innerHTML = '<li class="muted">Suggestions will appear here as you type.</li>';
    }
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function resetToEmpty() {
    renderResult({
      length: 0,
      score: 0,
      label: 'empty',
      entropy_bits: 0,
      checks: {},
      patterns_found: [],
      is_common_password: false,
      suggestions: [],
    });
  }

  async function analyze(password) {
    if (!password) {
      resetToEmpty();
      return;
    }
    try {
      const res = await fetch('/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      if (!res.ok) throw new Error('analysis failed');
      const result = await res.json();
      renderResult(result);
    } catch (err) {
      console.error(err);
    }
  }

  input.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    const value = input.value;
    debounceTimer = setTimeout(() => analyze(value), 180);
  });

  generateBtn.addEventListener('click', async () => {
    generateBtn.disabled = true;
    generateBtn.textContent = 'Generating…';
    try {
      const res = await fetch('/generate?length=16');
      const data = await res.json();
      input.type = 'text';
      eyeOpen.style.display = 'none';
      eyeClosed.style.display = 'block';
      input.value = data.password;
      renderResult(data.analysis);
    } catch (err) {
      console.error(err);
    } finally {
      generateBtn.disabled = false;
      generateBtn.textContent = 'Generate strong password';
    }
  });

  resetToEmpty();
})();
