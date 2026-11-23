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
  // The public entropy calculator must enforce the generator's exact input
  // contract. Otherwise truthy strings such as { digit: 'false' } silently
  // overstate the bits attributed to a secret the generator would reject.
  if (typeof digit !== 'boolean' || typeof symbol !== 'boolean') {
    throw new TypeError('Digit and symbol options must be boolean.');
  }
  return pairCount * Math.log2(DICTIONARY.combinationsPerPair) +
    (digit ? Math.log2(10) : 0) + (symbol ? Math.log2(SYMBOLS.length) : 0);
}

/**
 * Find the smallest number of word pairs meeting a chosen mathematical
 * entropy target under the optional digit/symbol choices.
 * Does not generate or retain any secret.
 */
export function minimumPassphrasePairs({ digit = false, symbol = false } = {}, targetBits = 80) {
  if (typeof digit !== 'boolean' || typeof symbol !== 'boolean') {
    throw new TypeError('Digit and symbol options must be boolean.');
  }
  if (!Number.isFinite(targetBits) || targetBits <= 0 || targetBits > 256) {
    throw new RangeError('Target entropy must be between 0 and 256 bits.');
  }
  for (let pairs = 4; pairs <= 12; pairs++) {
    if (calculateEntropy(pairs, { digit, symbol }) >= targetBits) return pairs;
  }
  return null;
}

/**
 * Length range for every possible secret under the selected word-pair rules.
 * No random draws and no generated string are created or retained. Each pair
 * contains an internal hyphen, while separators join whole pairs only.
 * This predicts code-unit lengths for the ASCII built-in dictionaries.
 */
export function passphraseLengthBounds({
  pairs = DEFAULT_PAIR_COUNT, separator = '-', digit = false, symbol = false,
} = {}) {
  if (!ALLOWED_SEPARATORS.has(separator)) throw new RangeError('Unsupported separator.');
  if (typeof digit !== 'boolean' || typeof symbol !== 'boolean') {
    throw new TypeError('Digit and symbol options must be boolean.');
  }
  // Reuse the exact pair-count range accepted by createPassphrase().
  calculateEntropy(pairs, { digit, symbol });
  const lengths = words => words.map(word => word.length);
  const adjectivesLengths = lengths(adjectives);
  const nounsLengths = lengths(nouns);
  const prefixLength = (pairs - 1) * separator.length +
    (digit ? 1 : 0) + (symbol ? 1 : 0);
  return {
    minimum: pairs * (Math.min(...adjectivesLengths) + 1 + Math.min(...nounsLengths)) + prefixLength,
    maximum: pairs * (Math.max(...adjectivesLengths) + 1 + Math.max(...nounsLengths)) + prefixLength,
    pairCount: pairs,
  };
}

/**
 * Check worst/best-case compatibility with an external character limit.
 * This is a policy planner, not a generator. A "variable" result means
 * some possible random phrases fit and others do not; it must not be
 * represented as guaranteed compatibility.
 */
export function passphraseLengthFit(options = {}, maxCharacters = 64) {
  if (!Number.isSafeInteger(maxCharacters) || maxCharacters < 1 ||
      maxCharacters > 1024) {
    throw new RangeError('Account maximum must be 1–1,024 characters.');
  }
  const { minimum, maximum } = passphraseLengthBounds(options);
  return {
    minimum, maximum, maxCharacters,
    fit: maximum <= maxCharacters ? 'guaranteed' :
      minimum > maxCharacters ? 'impossible' : 'variable',
  };
}

/**
 * Find the smallest permitted pair count satisfying the entropy target AND
 * guaranteeing that even the longest possible randomly chosen phrase fits.
 * Returns null when no safe recommendation can satisfy both requirements.
 * No random data is drawn, generated, stored or transmitted.
 */
export function minimumPassphrasePairsWithinLimit(
  { separator = '-', digit = false, symbol = false } = {},
  targetBits = 80,
  maxCharacters = 64,
) {
  const minimum = minimumPassphrasePairs({ digit, symbol }, targetBits);
  if (minimum === null) return null;
  const fit = passphraseLengthFit(
    { pairs: minimum, separator, digit, symbol }, maxCharacters,
  );
  // More pairs can only increase output length, so no later pair count
  // could meet the same length cap if this minimal-entropy count fails.
  return fit.fit === 'guaranteed' ? minimum : null;
}

/**
 * Generate an unpredictable passphrase from uniform independent choices.
 * The returned string is never persisted or transmitted by this library.
 * @param {{pairs?:number, separator?:string, digit?:boolean, symbol?:boolean, maxCharacters?:number}} options
 *   Optional hard limit: refuse to draw ANY secret unless every possible
 *   combination fits. Never truncate or redraw from a restricted subset.
 */
export function createPassphrase(options = {}) {
  const { pairs = DEFAULT_PAIR_COUNT, separator = '-', digit = false, symbol = false, maxCharacters } = options;
  if (!ALLOWED_SEPARATORS.has(separator)) throw new RangeError('Unsupported separator.');
  if (typeof digit !== 'boolean' || typeof symbol !== 'boolean')
    throw new TypeError('Digit and symbol options must be boolean.');
  const bits = calculateEntropy(pairs, { digit, symbol });
  if (maxCharacters !== undefined) {
    // Validate BEFORE requesting any randomness. Re-rolling only oversized
    // choices would skew the original word distribution and invalidate the
    // displayed independent-choice entropy.
    const fit = passphraseLengthFit({ pairs, separator, digit, symbol }, maxCharacters);
    if (fit.fit !== 'guaranteed') {
      throw new RangeError('Passphrase cannot be guaranteed to fit the maximum. Choose fewer pairs or a larger limit.');
    }
  }
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
function passwordSettings({ length = 20, lower = true, upper = true, numbers = true, special = true, excludeAmbiguous = false, requireEach = false, maxCharacters = null } = {}) {
  if (!Number.isInteger(length) || length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH) {
    throw new RangeError('Choose a password length between 12 and 64 characters.');
  }
  if (maxCharacters !== null && (!Number.isInteger(maxCharacters) || maxCharacters < MIN_PASSWORD_LENGTH || maxCharacters > MAX_PASSWORD_LENGTH)) {
    throw new RangeError('Maximum password length must be between 12 and 64 characters.');
  }
  if (maxCharacters !== null && length > maxCharacters) throw new RangeError('Selected password length exceeds the enforced maximum.');
  for (const setting of [lower, upper, numbers, special, excludeAmbiguous, requireEach]) {
    if (typeof setting !== 'boolean') throw new TypeError('Character options must be boolean.');
  }
  const selected = { lower, upper, numbers, special };
  const groups = Object.keys(PASSWORD_ALPHABETS)
    .filter(key => selected[key])
    .map(key => ({
      name: key,
      characters: [...PASSWORD_ALPHABETS[key]]
        .filter(char => !excludeAmbiguous || !AMBIGUOUS.has(char)).join(''),
    }));
  // Removing ambiguous characters happens before sampling or entropy math.
  const alphabet = groups.map(group => group.characters).join('');
  if (!alphabet) throw new RangeError('Enable at least one character set.');
  if (requireEach && groups.some(group => !group.characters.length)) {
    throw new RangeError('Each required character group must have eligible characters.');
  }
  return { alphabet, length, selected, excludeAmbiguous, requireEach, groups, maxCharacters };
}

/**
 * Probability that an independent uniform draw contains every required class.
 * Inclusion-exclusion is exact mathematically; all powers are ratios <= 1
 * to avoid overflowing for large password lengths.
 */
function coverageProbability(groups, alphabetLength, length) {
  if (groups.length <= 1) return 1;
  let probability = 0;
  for (let mask = 0; mask < (1 << groups.length); mask++) {
    let excluded = 0, bits = 0;
    for (let index = 0; index < groups.length; index++) {
      if (mask & (1 << index)) {
        excluded += groups[index].characters.length;
        bits++;
      }
    }
    const term = ((alphabetLength - excluded) / alphabetLength) ** length;
    probability += bits % 2 === 0 ? term : -term;
  }
  if (!(probability > 0 && probability <= 1.0000001)) {
    throw new RangeError('Unable to calculate category-coverage entropy.');
  }
  return Math.min(1, probability);
}

/**
 * Exact model entropy for the actual uniformly selected output space:
 *  - unrestricted: length * log2(alphabet size)
 *  - all categories required: subtract the probability mass rejected
 *    by category coverage, using uniform rejection sampling.
 */
export function calculatePasswordEntropy(options = {}) {
  const settings = passwordSettings(options);
  const bits = settings.length * Math.log2(settings.alphabet.length);
  return settings.requireEach ?
    bits + Math.log2(coverageProbability(
      settings.groups, settings.alphabet.length, settings.length,
    )) : bits;
}

/**
 * Find the smallest permitted password length meeting a random-choice
 * entropy target under the exact selected alphabet and coverage constraints.
 * This is planning math, not proof of protection from online attacks.
 * Returns null if no permitted length can meet the requested target.
 */
export function minimumPasswordLength(options = {}, targetBits = 80) {
  if (!Number.isFinite(targetBits) || targetBits <= 0 || targetBits > 256) {
    throw new RangeError('Target entropy must be a number from 0 to 256 bits.');
  }
  const requested = { ...options, length: MIN_PASSWORD_LENGTH };
  // Fail early for an invalid alphabet or contradictory group selections.
  passwordSettings(requested);
  for (let length = MIN_PASSWORD_LENGTH; length <= MAX_PASSWORD_LENGTH; length++) {
    if (calculatePasswordEntropy({ ...options, length }) >= targetBits) {
      return length;
    }
  }
  return null;
}

/**
 * Produce a random character password using Web Crypto only.
 * The returned secret stays in memory unless the caller explicitly copies it.
 */
export function createRandomPassword(options = {}) {
  const settings = passwordSettings(options);
  const { alphabet, length, selected, excludeAmbiguous, requireEach, groups } = settings;
  const entropy = calculatePasswordEntropy(options);
  // Each attempted password is an independent uniform draw over the full
  // alphabet. Rejection therefore leaves a uniform distribution over the
  // subset containing all selected groups (no biased "forced character"
  // placement or shuffling).
  for (let attempt = 0; attempt < 1024; attempt++) {
    let password = '';
    for (let index = 0; index < length; index++) {
      password += alphabet[secureIndex(alphabet.length)];
    }
    if (requireEach && groups.some(group =>
      ![...password].some(character => group.characters.includes(character))
    )) continue;
    return {
      password,
      bits: entropy,
      length,
      alphabetSize: alphabet.length,
      characterSets: selected,
      excludeAmbiguous,
      requireEach,
    };
  }
  throw new Error('Unable to meet the selected character requirements securely.');
}
