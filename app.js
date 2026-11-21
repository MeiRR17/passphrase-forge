import { createPassphrase, calculateEntropy, DICTIONARY } from './src/generator.js';

const $ = id => document.getElementById(id);
const pairs = $('pairs');
const separator = $('separator');
const digit = $('digit');
const symbol = $('symbol');
const textarea = $('phrase');
const reveal = $('reveal');
const copy = $('copy');
let secret = '';
let concealed = false;

function options() {
  return {
    pairs: Number(pairs.value),
    separator: separator.value,
    digit: digit.checked,
    symbol: symbol.checked,
  };
}
function status(message, error = false) {
  const el = $('status');
  el.textContent = message;
  el.className = 'status' + (error ? ' error' : '');
}
function showSecret() {
  textarea.value = concealed && secret ? '•'.repeat(secret.length) : secret;
  reveal.textContent = concealed ? 'Reveal passphrase' : 'Hide passphrase';
}
function clearSecret() {
  secret = '';
  concealed = false;
  textarea.value = '';
  copy.disabled = reveal.disabled = true;
  reveal.textContent = 'Hide passphrase';
}
function explainEntropy() {
  const opts = options();
  const bits = calculateEntropy(opts.pairs, opts);
  $('pairs-value').textContent = opts.pairs + (opts.pairs === 1 ? ' pair' : ' pairs');
  $('bits').textContent = bits.toFixed(1).replace(/\.0$/, '');
  const label = bits < 60 ? 'Add more pairs' : bits < 80 ? 'High' : 'Very high';
  $('grade').textContent = label;
  $('meter-fill').style.width = Math.min(100, bits / 144 * 100) + '%';
  $('entropy-meter').setAttribute('aria-valuenow', String(Math.round(bits)));
  $('entropy-explanation').textContent =
    opts.pairs + ' independent choices among ' +
    DICTIONARY.combinationsPerPair.toLocaleString('en-US') +
    ' adjective–noun combinations each' +
    (opts.digit ? ', plus one uniform random digit' : '') +
    (opts.symbol ? ', plus one uniform random symbol' : '') +
    '. Approximately ' + bits.toFixed(1) +
    ' bits of random-choice entropy. This is not a guarantee against theft, phishing or weak account security.';
}

function generate() {
  try {
    const result = createPassphrase(options());
    secret = result.phrase;
    concealed = false;
    copy.disabled = reveal.disabled = false;
    showSecret();
    explainEntropy();
    status('New passphrase generated locally. Store it somewhere secure.');
  } catch (error) {
    clearSecret();
    status(error.message || 'Secure generation failed.', true);
  }
}

for (const control of [pairs, separator, digit, symbol]) {
  control.addEventListener('input', () => {
    clearSecret();
    explainEntropy();
    status('Settings changed. Generate a new passphrase to apply them.');
  });
}
$('generate').addEventListener('click', generate);
$('regenerate').addEventListener('click', generate);
reveal.addEventListener('click', () => {
  if (!secret) return;
  concealed = !concealed;
  showSecret();
  status(concealed ? 'Passphrase concealed on screen.' : 'Passphrase visible on screen.');
});
copy.addEventListener('click', async () => {
  if (!secret) return;
  if (!navigator.clipboard?.writeText) {
    status('Clipboard API is unavailable. Reveal and copy the phrase manually.', true);
    return;
  }
  try {
    await navigator.clipboard.writeText(secret);
    status('Passphrase copied. Your clipboard may remain accessible to other apps: clear it after saving the phrase.');
  } catch {
    status('Copy was blocked by your browser. Reveal the passphrase and copy manually.', true);
  }
});

document.addEventListener('visibilitychange', () => {
  if (document.hidden && secret) {
    concealed = true;
    showSecret();
  }
});

// Do not write generated secrets to localStorage, sessionStorage, URLs or logs.
clearSecret();
explainEntropy();
