import { createPassphrase, calculateEntropy, minimumPassphrasePairs, minimumPassphrasePairsWithinLimit, passphraseLengthFit, passphraseLengthBounds, DICTIONARY, createRandomPassword, calculatePasswordEntropy, minimumPasswordLength, PASSWORD_ALPHABETS } from './src/generator.js';

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
const enforcePhraseMaximum = $('enforce-phrase-maximum');
let secret = '';
let concealed = false;
let secretRevision = 0;
const VISIBLE_SECRET_MS = 30_000;
let concealTimer = null;

function cancelConcealTimer() {
  if (concealTimer !== null) clearTimeout(concealTimer);
  concealTimer = null;
}
function scheduleConceal() {
  cancelConcealTimer();
  if (!secret || concealed) return;
  const revision = secretRevision;
  concealTimer = setTimeout(() => {
    concealTimer = null;
    if (!secret || concealed || revision !== secretRevision) return;
    concealed = true;
    showSecret();
    status('Secret hidden after 30 seconds. Reveal it again if you still need to save it.');
  }, VISIBLE_SECRET_MS);
}
function concealOnBlur() {
  if (!secret || concealed) return;
  cancelConcealTimer();
  concealed = true;
  showSecret();
  status('Secret hidden because the page lost focus. Reveal it again when needed.');
}

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
    maxCharacters: $('enforce-password-maximum').checked ? Number($('password-maximum').value) : null,
  };
}
function passwordAlphabetSize(options) {
  const included = Object.entries(PASSWORD_ALPHABETS)
    .filter(([key]) => options[key])
    .map(([,chars]) => chars).join('');
  return options.excludeAmbiguous ?
    [...included].filter(char => !'0Oo1lIi'.includes(char)).length : included.length;
}
function recommendedPairs(options = wordOptions()) {
  try {
    const targetBits = Number($('phrase-entropy-target').value);
    const maximum = Number($('phrase-maximum').value);
    const required = maximum ?
      minimumPassphrasePairsWithinLimit(options, targetBits, maximum) :
      minimumPassphrasePairs(options, targetBits);
    $('pair-recommendation').textContent = required === null ?
      (maximum
        ? 'No 4–12 pair configuration meets both ' + targetBits +
          ' bits and a guaranteed ' + maximum + '-character maximum.'
        : 'This configuration cannot reach ' + targetBits + ' bits within 12 word pairs.') :
      'Minimum calculated length: ' + required + ' word pairs for at least ' +
      targetBits + ' bits of random-choice entropy' +
      (maximum ? ', guaranteed to fit within ' + maximum + ' characters' : '') +
      '. This is not an account-security guarantee.';
    $('apply-recommended-pairs').disabled = required === null ||
      required === Number(pairs.value);
    return required;
  } catch (error) {
    $('pair-recommendation').textContent = error.message;
    $('apply-recommended-pairs').disabled = true;
    return null;
  }
}

function recommendedLength(options = passwordOptions()) {
  try {
    const targetBits = Number($('entropy-target').value);
    const length = minimumPasswordLength({ ...options, maxCharacters: null }, targetBits);
    const maximum = Number($('password-maximum').value);
    const fits = length !== null && (!maximum || length <= maximum);
    $('target-recommendation').textContent = length === null ?
      'This alphabet cannot reach ' + targetBits + ' bits within the 64-character limit.' :
      !fits ? 'The minimum length for ' + targetBits + ' bits is ' + length + ' characters, above the selected ' + maximum + '-character maximum.' :
      'Minimum calculated length: ' + length + ' characters for at least ' + targetBits +
      ' bits of ideal random-choice entropy' + (maximum ? ', within the selected ' + maximum + '-character maximum' : '') +
      '. This is not an account-security guarantee.';
    $('apply-recommended-length').disabled = !fits || length === Number(passwordLength.value);
    return fits ? length : null;
  } catch (error) {
    $('target-recommendation').textContent = error.message;
    $('apply-recommended-length').disabled = true;
    return null;
  }
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
  cancelConcealTimer();
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
      const maximum = Number($('password-maximum').value);
      $('enforce-password-maximum').disabled = maximum === 0;
      if (!maximum) $('enforce-password-maximum').checked = false;
      $('generate').disabled = $('regenerate').disabled = Boolean(chars.maxCharacters && chars.length > chars.maxCharacters);
      $('phrase-length-estimate').textContent = '';
      recommendedLength(chars);
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
      recommendedPairs(words);
      const limits = passphraseLengthBounds(words);
      const maximum = Number($('phrase-maximum').value);
      enforcePhraseMaximum.disabled = maximum === 0;
      if (!maximum) enforcePhraseMaximum.checked = false;
      const enforcing = enforcePhraseMaximum.checked;
      const fit = maximum ? passphraseLengthFit(words, maximum) : null;
      const allowed = !enforcing || fit?.fit === 'guaranteed';
      $('generate').disabled = $('regenerate').disabled = !allowed;
      const compatibility = fit?.fit === 'guaranteed'
        ? (enforcing
          ? ' Strict maximum enabled: every generated choice fits.'
          : ' Every generated choice fits the selected maximum; enforcement is off.')
        : fit?.fit === 'impossible'
          ? (enforcing
            ? ' Strict maximum blocks generation: no possible choice fits.'
            : ' No possible choice fits; the selected limit is advisory only.')
          : fit?.fit === 'variable'
            ? (enforcing
              ? ' Strict maximum blocks generation because some possible choices are too long. Adjust pairs or disable enforcement.'
              : ' Some choices could exceed the maximum; this limit is advisory unless enforcement is enabled.')
            : '';
      $('phrase-length-estimate').textContent = 'Possible output length: ' + limits.minimum +
        '–' + limits.maximum + ' characters across the selected word pairs, separator and extras. ' +
        'The exact length depends on the random words drawn.' + compatibility;
      $('entropy-explanation').textContent =
        words.pairs + ' independent choices among ' + DICTIONARY.combinationsPerPair.toLocaleString('en-US') +
        ' adjective–noun combinations each' +
        (words.digit ? ', plus one random digit' : '') +
        (words.symbol ? ', plus one random symbol' : '') +
        '. Approximately ' + bits.toFixed(1) + ' bits of random-choice entropy.';
    }
    return true;
  } catch (error) {
    // Fail closed: a previously valid setting must not leave generation
    // controls enabled while the entropy/preflight check is failing.
    $('generate').disabled = $('regenerate').disabled = true;
    $('bits').textContent = '—';
    $('grade').textContent = 'Invalid generation settings';
    $('meter-fill').style.width = '0';
    $('entropy-meter').setAttribute('aria-valuenow','0');
    $('entropy-explanation').textContent = error.message;
    $('phrase-length-estimate').textContent = '';
    if (usingPassword) recommendedLength(passwordOptions());
    else recommendedPairs(wordOptions());
    return false;
  }
}
function generate() {
  try {
    const usingPassword = activeMode() === 'password';
    const result = usingPassword
      ? createRandomPassword(passwordOptions())
      : createPassphrase({
        ...wordOptions(),
        ...(enforcePhraseMaximum.checked
          ? { maxCharacters: Number($('phrase-maximum').value) }
          : {}),
      });
    secretRevision++;
    secret = activeMode() === 'password' ? result.password : result.phrase;
    concealed = false;
    copy.disabled = reveal.disabled = clear.disabled = false;
    showSecret();
    scheduleConceal();
    explainEntropy();
    status('New secret generated locally. Its visible display will be hidden after 30 seconds.');
  } catch (error) {
    clearSecret();
    status(error.message || 'Secure generation failed.', true);
  }
}

for (const control of [pairs, separator, digit, symbol, mode, passwordLength,
  $('charset-lower'), $('charset-upper'), $('charset-numbers'), $('charset-special'),
  $('exclude-ambiguous'), $('require-each'), $('password-maximum'), $('enforce-password-maximum')]) {
  control.addEventListener('input', () => {
    clearSecret();
    explainEntropy();
    status('Settings changed. Generate a new passphrase to apply them.');
  });
}
$('password-maximum').addEventListener('change', () => {
  if ($('enforce-password-maximum').checked) clearSecret();
  explainEntropy();
  status('Password maximum changed. Review the selected length and regenerate if needed.');
});
$('enforce-password-maximum').addEventListener('change', () => {
  clearSecret(); explainEntropy();
  status($('enforce-password-maximum').checked ? 'Strict password maximum enabled. Configurations above the selected cap are blocked.' : 'Password maximum is advisory only.');
});
$('entropy-target').addEventListener('change', () => {
  // Planning guidance never generates or clears an existing secret.
  if (activeMode() === 'password') recommendedLength();
});
$('phrase-entropy-target').addEventListener('change', () => {
  if (activeMode() === 'phrase') recommendedPairs();
});
$('phrase-maximum').addEventListener('change', () => {
  // When enforcement is on, the previous secret may not satisfy the NEW cap.
  // Without enforcement the maximum remains informational only.
  const previouslyEnforcing = enforcePhraseMaximum.checked;
  if (!Number($('phrase-maximum').value)) enforcePhraseMaximum.checked = false;
  if (previouslyEnforcing) clearSecret();
  if (activeMode() === 'phrase') explainEntropy();
  if (previouslyEnforcing) status('Maximum changed. The previous secret was cleared; generate again using the new limit.');
});
enforcePhraseMaximum.addEventListener('change', () => {
  // Invalidate secrets created without this setting; never present an older
  // passphrase as meeting a newly selected strict account maximum.
  clearSecret();
  explainEntropy();
  status(enforcePhraseMaximum.checked
    ? 'Strict maximum enabled. Incompatible configurations cannot generate any secret.'
    : 'Strict maximum disabled. The selected account length is now advisory only.');
});
$('apply-recommended-pairs').addEventListener('click', () => {
  if (activeMode() !== 'phrase') return;
  const required = recommendedPairs();
  if (required === null || required === Number(pairs.value)) return;
  pairs.value = String(required);
  // This uses the existing setting-change handler, which clears stale secrets.
  pairs.dispatchEvent(new Event('input', { bubbles: true }));
});
$('apply-recommended-length').addEventListener('click', () => {
  if (activeMode() !== 'password') return;
  const length = recommendedLength();
  if (length === null) return;
  passwordLength.value = String(length);
  // Reuse the existing settings path, which invalidates the previous secret
  // before the next password is generated.
  passwordLength.dispatchEvent(new Event('input', { bubbles: true }));
});
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
  if (concealed) cancelConcealTimer();
  else scheduleConceal();
  status(concealed ? 'Secret hidden on screen.' : 'Secret revealed. It will be hidden after 30 seconds.');
});
copy.addEventListener('click', async () => {
  if (!secret) return;
  if (!navigator.clipboard?.writeText) {
    status('Clipboard API is unavailable. Reveal and copy the secret manually.', true);
    return;
  }
  const copiedRevision = secretRevision;
  const copiedSecret = secret;
  // Prevent simultaneous writes of this secret. A new generation or Clear
  // changes the revision, so an old write must not alter new button state.
  copy.disabled = true;
  try {
    await navigator.clipboard.writeText(copiedSecret);
    if (copiedRevision !== secretRevision) {
      status('Copy completed for a previous secret. The clipboard may still hold it; replace or clear the clipboard.', true);
      return;
    }
    // The clipboard may retain the secret, but do not leave it visible in the
    // textarea while the user switches to their password manager.
    cancelConcealTimer();
    concealed = true;
    showSecret();
    status('Secret copied and hidden on screen. The clipboard can still be read by other apps; clear it after saving.');
  } catch {
    if (copiedRevision === secretRevision) {
      status('Copy was blocked by your browser. Reveal and copy the secret manually.', true);
    }
  } finally {
    // Never reenable a cleared or superseded secret because an older
    // asynchronous clipboard operation happened to finish later.
    if (copiedRevision === secretRevision) copy.disabled = !secret;
  }
});

document.addEventListener('visibilitychange', () => {
  if (document.hidden) concealOnBlur();
});
window.addEventListener('blur', concealOnBlur);

// Do not write generated secrets to localStorage, sessionStorage, URLs or logs.
clearSecret();
explainEntropy();
