/**
 * Cryptographically random, memorable passphrase generation.
 *
 * Every token is a uniform adjective+noun combination. Entropy is based on
 * the actual curated word-list sizes, never on a password-strength guess.
 * There is intentionally no Math.random fallback.
 */

const ADJECTIVES = [
  'amber','ancient','arctic','azure','bamboo','brave','bright','calm',
  'cedar','charming','clear','clever','cloudy','cobalt','coral','cosmic',
  'crimson','curious','daring','dawn','distant','eager','echoing','electric',
  'emerald','fabled','fern','floral','flying','forest','frosty','gentle',
  'glowing','golden','grand','green','happy','hidden','honest','ivory',
  'jade','jolly','kind','lavender','lively','lunar','maple','mellow',
  'minty','misty','noble','orange','patient','pearl','quiet','rapid',
  'rising','ruby','silver','solar','steady','sunny','velvet','wild',
];
const NOUNS = [
  'acorn','anchor','apple','arch','badger','beacon','berry','bird',
  'boat','book','bridge','brook','cabin','canyon','castle','cave',
  'cloud','comet','coral','creek','dolphin','dragon','dream','eagle',
  'falcon','feather','field','flower','forest','fox','garden','glacier',
  'harbor','hill','island','jewel','lantern','leaf','lemon','lighthouse',
  'meadow','meteor','moon','mountain','ocean','orchard','otter','owl',
  'panda','pebble','piano','planet','rainbow','river','rocket','sail',
  'shore','sparrow','star','stone','sunrise','tiger','valley','willow',
];
const SYMBOLS = '!@#$%&*?';
const DEFAULT_PAIR_COUNT = 6;
const ALLOWED_SEPARATORS = new Set([' ', '-', '.', '_']);
const secureCrypto = () => {
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') {
    throw new Error('Secure randomness is unavailable. Open this page over HTTPS or localhost.');
  }
  return globalThis.crypto;
};

/** A bias-free bounded random integer from a secure 32-bit source. */
export function secureIndex(limit) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 65536)
    throw new RangeError('Invalid random range.');
  const engine = secureCrypto();
  const boundary = Math.floor(0x100000000 / limit) * limit;
  const chunk = new Uint32Array(1);
  let value;
  do {
    engine.getRandomValues(chunk);
    value = chunk[0];
  } while (value >= boundary);
  return value % limit;
}

function uniqueWords(list, label) {
  const words = [...new Set(list)];
  if (words.length !== list.length || words.some(w => !/^[a-z]+$/.test(w))) {
    throw new Error('Invalid built-in word list: ' + label);
  }
  return Object.freeze(words);
}
const adjectives = uniqueWords(ADJECTIVES, 'adjectives');
const nouns = uniqueWords(NOUNS, 'nouns');

/** Public non-sensitive information about the uniform generator. */
export const DICTIONARY = Object.freeze({
  adjectives: adjectives.length,
  nouns: nouns.length,
  combinationsPerPair: adjectives.length * nouns.length,
});

export function calculateEntropy(pairCount, { digit = false, symbol = false } = {}) {
  if (!Number.isInteger(pairCount) || pairCount < 4 || pairCount > 12)
    throw new RangeError('Choose 4–12 word pairs.');
  return pairCount * Math.log2(DICTIONARY.combinationsPerPair) +
    (digit ? Math.log2(10) : 0) + (symbol ? Math.log2(SYMBOLS.length) : 0);
}

/**
 * Generate an unpredictable passphrase from uniform independent choices.
 * The returned string is never persisted or transmitted by this library.
 * @param {{pairs?:number, separator?:string, digit?:boolean, symbol?:boolean}} options
 */
export function createPassphrase(options = {}) {
  const { pairs = DEFAULT_PAIR_COUNT, separator = '-', digit = false, symbol = false } = options;
  if (!ALLOWED_SEPARATORS.has(separator)) throw new RangeError('Unsupported separator.');
  if (typeof digit !== 'boolean' || typeof symbol !== 'boolean')
    throw new TypeError('Digit and symbol options must be boolean.');
  const bits = calculateEntropy(pairs, { digit, symbol });
  const words = [];
  for (let i = 0; i < pairs; i++) {
    words.push(adjectives[secureIndex(adjectives.length)] + '-' + nouns[secureIndex(nouns.length)]);
  }
  const suffix = (digit ? String(secureIndex(10)) : '') +
    (symbol ? SYMBOLS[secureIndex(SYMBOLS.length)] : '');
  return {
    phrase: words.join(separator) + suffix,
    bits,
    pairs,
    separator,
    digit,
    symbol,
    choicesPerPair: DICTIONARY.combinationsPerPair,
  };
}

/**
 * Unambiguous character-set selections for random character passwords.
 * Passwords are drawn uniformly from the combined set; they do not
 * guarantee one character from each enabled class.
 */
export const PASSWORD_ALPHABETS = Object.freeze({
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  numbers: '0123456789',
  special: '!@#$%&*?_-+=',
});
const AMBIGUOUS = new Set('0Oo1lIi');
const MAX_PASSWORD_LENGTH = 64;
const MIN_PASSWORD_LENGTH = 12;
function passwordSettings({ length = 20, lower = true, upper = true, numbers = true, special = true, excludeAmbiguous = false } = {}) {
  if (!Number.isInteger(length) || length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH) {
    throw new RangeError('Choose a password length between 12 and 64 characters.');
  }
  for (const setting of [lower, upper, numbers, special, excludeAmbiguous]) {
    if (typeof setting !== 'boolean') throw new TypeError('Character options must be boolean.');
  }
  const selected = { lower, upper, numbers, special };
  let alphabet = Object.keys(PASSWORD_ALPHABETS)
    .filter(key => selected[key])
    .map(key => PASSWORD_ALPHABETS[key])
    .join('');
  // Filtering occurs *before* random sampling: the probability model
  // uses the actual surviving alphabet, without altering sampling weights.
  if (excludeAmbiguous) alphabet = [...alphabet].filter(char => !AMBIGUOUS.has(char)).join('');
  if (!alphabet) throw new RangeError('Enable at least one character set.');
  return { alphabet, length, selected, excludeAmbiguous };
}

/** Mathematical uncertainty for uniform independent character selection. */
export function calculatePasswordEntropy(options = {}) {
  const settings = passwordSettings(options);
  return settings.length * Math.log2(settings.alphabet.length);
}

/**
 * Produce a random character password using Web Crypto only.
 * The returned secret stays in memory unless the caller explicitly copies it.
 */
export function createRandomPassword(options = {}) {
  const { alphabet, length, selected, excludeAmbiguous } = passwordSettings(options);
  let password = '';
  for (let index = 0; index < length; index++) {
    password += alphabet[secureIndex(alphabet.length)];
  }
  return {
    password,
    bits: length * Math.log2(alphabet.length),
    length,
    alphabetSize: alphabet.length,
    characterSets: selected,
    excludeAmbiguous,
  };
}
