import { createPassphrase, calculateEntropy, DICTIONARY, createRandomPassword, calculatePasswordEntropy, PASSWORD_ALPHABETS } from './src/generator.js';

const $ = id => document.getElementById(id);
const pairs = $('pairs');
const separator = $('separator');
const digit = $('digit');
const symbol = $('symbol');
const textarea = $('phrase');
const reveal = $('reveal');
const copy = $('copy');
const clear = $('clear');
const mode = $('generator-mode');
const passwordLength = $('password-length');
let secret = '';
let concealed = false;
let secretRevision = 0;

function wordOptions() {
  return {
    pairs: Number(pairs.value),
    separator: separator.value,
    digit: digit.checked,
    symbol: symbol.checked,
  };
}
function passwordOptions() {
  return {
    length: Number(passwordLength.value),
    lower: $('charset-lower').checked,
    upper: $('charset-upper').checked,
    numbers: $('charset-numbers').checked,
    special: $('charset-special').checked,
    excludeAmbiguous: $('exclude-ambiguous').checked,
    requireEach: $('require-each').checked,
  };
}
function passwordAlphabetSize(options) {
  const included = Object.entries(PASSWORD_ALPHABETS)
    .filter(([key]) => options[key])
    .map(([,chars]) => chars).join('');
  return options.excludeAmbiguous ?
    [...included].filter(char => !'0Oo1lIi'.includes(char)).length : included.length;
}
function activeMode() { return mode.value === 'password' ? 'password' : 'phrase'; }
function status(message, error = false) {
  const el = $('status');
  el.textContent = message;
  el.className = 'status' + (error ? ' error' : '');
}
function showSecret() {
  textarea.value = concealed && secret ? '•'.repeat(secret.length) : secret;
  reveal.textContent = concealed ? 'Reveal secret' : 'Hide secret';
}
function clearSecret() {
  secretRevision++;
  secret = '';
  concealed = false;
  textarea.value = '';
  copy.disabled = reveal.disabled = clear.disabled = true;
  reveal.textContent = 'Hide secret';
}
function explainEntropy() {
  const usingPassword = activeMode() === 'password';
  const pairCount = Number(pairs.value);
  $('pairs-value').textContent = pairCount + ' pairs';
  $('password-length-value').textContent = passwordLength.value + ' characters';
  $('word-options').hidden = usingPassword;
  $('password-options').hidden = !usingPassword;
  $('result-heading').textContent = usingPassword ? 'Your new password' : 'Your new passphrase';
  copy.textContent = usingPassword ? 'Copy password' : 'Copy passphrase';
  $('generate').textContent = usingPassword ? '✳ Generate password' : '✳ Generate passphrase';
  try {
    const words = wordOptions(), chars = passwordOptions();
    const bits = usingPassword ? calculatePasswordEntropy(chars) : calculateEntropy(words.pairs, words);
    const width = Math.min(100, bits / 144 * 100);
    $('bits').textContent = bits.toFixed(1).replace(/\.0$/, '');
    $('grade').textContent = bits < 60 ? 'Add more randomness' : bits < 80 ? 'High' : 'Very high';
    $('meter-fill').style.width = width + '%';
    $('entropy-meter').setAttribute('aria-valuemax', String(Math.max(144, Math.ceil(bits))));
    $('entropy-meter').setAttribute('aria-valuenow', String(Math.round(bits)));
    if (usingPassword) {
      const alphabetSize = passwordAlphabetSize(chars);
      $('entropy-explanation').textContent =
        chars.length + ' independent character choices from an alphabet of ' + alphabetSize +
        ' symbols produce approximately ' + bits.toFixed(1) +
        ' bits. ' +
        (chars.requireEach ?
          'Every enabled character group is guaranteed by uniform rejection sampling.' :
          'Enabled character groups are possible, but not guaranteed to appear.') +
        (chars.excludeAmbiguous ? ' Look-alike characters are excluded before sampling.' : '');
    } else {
      $('entropy-explanation').textContent =
        words.pairs + ' independent choices among ' + DICTIONARY.combinationsPerPair.toLocaleString('en-US') +
        ' adjective–noun combinations each' +
        (words.digit ? ', plus one random digit' : '') +
        (words.symbol ? ', plus one random symbol' : '') +
        '. Approximately ' + bits.toFixed(1) + ' bits of random-choice entropy.';
    }
    return true;
  } catch (error) {
    $('bits').textContent = '—';
    $('grade').textContent = 'Select a character set';
    $('meter-fill').style.width = '0';
    $('entropy-meter').setAttribute('aria-valuenow','0');
    $('entropy-explanation').textContent = error.message;
    return false;
  }
}
function generate() {
  try {
    const result = activeMode() === 'password' ?
      createRandomPassword(passwordOptions()) : createPassphrase(wordOptions());
    secretRevision++;
    secret = activeMode() === 'password' ? result.password : result.phrase;
    concealed = false;
    copy.disabled = reveal.disabled = clear.disabled = false;
    showSecret();
    explainEntropy();
    status('New secret generated locally. Store it somewhere secure.');
  } catch (error) {
    clearSecret();
    status(error.message || 'Secure generation failed.', true);
  }
}

for (const control of [pairs, separator, digit, symbol, mode, passwordLength,
  $('charset-lower'), $('charset-upper'), $('charset-numbers'), $('charset-special'),
  $('exclude-ambiguous'), $('require-each')]) {
  control.addEventListener('input', () => {
    clearSecret();
    explainEntropy();
    status('Settings changed. Generate a new passphrase to apply them.');
  });
}
$('generate').addEventListener('click', generate);
$('regenerate').addEventListener('click', generate);
clear.addEventListener('click', () => {
  clearSecret();
  status('The generated secret was cleared from this page. The browser cannot erase external clipboard histories.');
});
reveal.addEventListener('click', () => {
  if (!secret) return;
  concealed = !concealed;
  showSecret();
  status(concealed ? 'Passphrase concealed on screen.' : 'Passphrase visible on screen.');
});
copy.addEventListener('click', async () => {
  if (!secret) return;
  if (!navigator.clipboard?.writeText) {
    status('Clipboard API is unavailable. Reveal and copy the secret manually.', true);
    return;
  }
  const copiedRevision = secretRevision;
  const copiedSecret = secret;
  try {
    await navigator.clipboard.writeText(copiedSecret);
    if (copiedRevision !== secretRevision) {
      status('Copy completed for a previous secret. The clipboard may still hold it; replace or clear the clipboard.', true);
      return;
    }
    status('Secret copied. Your clipboard may remain accessible to other apps: clear it after saving it.');
  } catch {
    if (copiedRevision === secretRevision) {
      status('Copy was blocked by your browser. Reveal the secret and copy manually.', true);
    }
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
