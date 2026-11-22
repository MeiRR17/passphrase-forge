# Passphrase Forge

Create memorable passphrases **or uniform random-character passwords** in a modern browser using **cryptographically secure randomness**. No signup, network service, analytics, storage of generated phrases, or third-party dependencies.

## Get started

Serve the repository root using a local HTTP server (required for browser ES modules):

    python3 -m http.server 8000

Visit http://localhost:8000, choose **Memorable word pairs** or **Random characters**, configure the options and select Generate. The application also works on static HTTPS hosting. Web Crypto must be available (HTTPS or localhost). If secure randomness is unavailable, generation stops rather than falling back to predictable randomness.

## How it works

Each pair is a randomly chosen adjective followed by a randomly chosen noun. The generator uses two curated 64-word lists, creating 4,096 possible adjective–noun combinations per pair. For example, a *sample-shaped* phrase could look like `quiet-lantern-bright-river`; never use an example string as a real secret.

Every list index is selected independently with `crypto.getRandomValues()` and rejection sampling to avoid modulo bias. The generator never uses `Math.random()`. List sizes are checked for duplicate entries.

**Random-choice entropy**, not a password “quality score,” is reported. With six independent pairs, the entropy is 6 × log2(4,096) = **72 bits**, assuming unpredictable generation and the full list available to an attacker. Adding a random digit gives log2(10) extra bits; one uniformly selected symbol from eight choices adds 3 more bits. Separators do **not** add entropy.

Passphrase length and entropy are calculated from actual generator choices; the result is not a claim of immunity to guessing, phishing, malware, breaches, or password-reuse attacks.

### Passphrase character-length bounds

Before generating a word-pair passphrase, the interface now displays the minimum and maximum possible **character lengths** for the selected number of pairs, separator, random-digit and random-symbol options. The pure `passphraseLengthBounds()` function uses the shortest and longest words from both built-in dictionaries, counts the hyphen inside each adjective–noun pair and the selected separator between pairs, and includes optional suffix characters. No secret or random choice is created by this calculation. The exact length of a generated secret depends on the selected words; the bounds can help evaluate maximum-length account restrictions, but do not verify the password policy of any external service. In character-password mode the length is already fixed by the slider.

API: `passphraseLengthBounds({ pairs: 6, separator: '-', digit: false, symbol: true })` returns `{ minimum, maximum, pairCount }` without touching the browser clipboard or storage.

### Account maximum-length compatibility planner

If an account service imposes a maximum secret length, choose **External account maximum length** (32, 48, 64, 96, 128 or 256 characters) in word-pair mode. The app compares the selected word-pair configuration's shortest and longest possible outputs against that limit: **guaranteed** (all outputs fit), **variable** (some may exceed the limit), or **impossible** (none fit). This calculation is deterministic, does not draw randomness, and never sends the limit to a network service. The length selector remains **advisory by default**. The separate opt-in **Enforce maximum when generating** checkbox makes the generator reject configurations unless their **worst-case** length fits. It does not shorten or redraw word choices, so the underlying uniform distribution and stated entropy remain unchanged. Switching enforcement on clears any existing generated secret; changing the selected maximum while enforcement is on also clears it. An incompatible configuration disables Generate and Regenerate until adjusted. No remote account policy is queried.

When a limit is selected, **Use suggested pairs** now recommends the smallest 4–12 pair count meeting both the chosen entropy target and a *guaranteed* maximum length. If no pair count can satisfy both, it explicitly reports no available recommendation rather than suggesting a shorter, weaker phrase. The underlying independent selections and entropy calculation do not change. Other account restrictions (minimum length, spaces, character classes, Unicode support) must still be reviewed separately.

Pure API: `passphraseLengthFit({ pairs: 6, separator: '-' }, 64)` returns bounds and `fit: 'guaranteed' | 'variable' | 'impossible'`; `minimumPassphrasePairsWithinLimit({ separator: '-', digit: false, symbol: false }, 80, 64)` returns the minimum compatible pair count or `null`. Neither planner generates a secret. For code that **requires** a strict maximum, use `createPassphrase({ pairs: 6, separator: '-', maxCharacters: 96 })`; the function throws `RangeError` *before* any random choices if the maximum cannot be guaranteed, and keeps its original uniform sampling if it can. The optional limit is a hard output-length bound, not validation of minimum lengths or other service restrictions.

### Word-pair entropy planner

Memorable-word mode also offers an **entropy-target planner** with targets of 64, 80, 96, 128 and 160 bits. It finds the smallest permitted number of independent adjective–noun pairs (4–12) needed for the chosen target, counting any enabled random digit or symbol. For example, 80 bits without extra characters requires 7 word pairs; the 160-bit option cannot be met within the 12-pair limit and reports that explicitly. The planner never creates a secret.

Call \`minimumPassphrasePairs({ digit: false, symbol: false }, 80)\` from the library. Choosing **Use suggested pairs** updates the slider and invalidates a previously generated secret, which must then be regenerated explicitly. Mathematical entropy estimates are not account-security guarantees.

### Character-password mode

Choose a length from **12–64** characters, and enable any combination of lowercase letters (26), uppercase letters (26), numbers (10) and symbols (12). By default, the generator selects **each position uniformly and independently** from the combined alphabet using the same Web Crypto rejection sampling. With alphabet size `N` and password length `L`, the unconstrained random-choice entropy is `L × log2(N)` bits. If the optional require-every-group rule is enabled, accepted passwords remain uniformly distributed over the qualifying subset and the entropy estimate is adjusted accordingly. There is no biased shuffle or insecure random fallback.

**Important:** By default, enabling a category makes its characters possible but does **not guarantee** that every enabled category appears. With the optional Require every selected group setting, each enabled category is guaranteed, with an entropy adjustment.

An optional **Require every selected group** switch rejects otherwise-uniform Web Crypto password candidates until the result includes at least one character from each enabled category. Rejection sampling is uniform over the valid password space; no character is forcibly inserted or shuffled. Entropy is adjusted to the number of valid strings using inclusion-exclusion, so the meter does not overstate the strength of a constrained password. The option is off by default. At most 1,024 candidate passwords are generated per request before an explicit failure; the generator never falls back to a weaker source. Choose `requireEach: true` when calling `createRandomPassword()` or `calculatePasswordEntropy()`.

An optional **Avoid look-alike characters** switch excludes `0`, `O`, `o`, `1`, `l`, `I`, and `i` from the combined alphabet. This is helpful when reading a password aloud or retyping it, but it decreases the alphabet size and therefore its entropy. The displayed entropy is recalculated using the actual filtered alphabet **before** cryptographic selection; the generator remains uniform and bias-free. If a service requires at least one character of every category, visually verify compliance or regenerate. Separators and word-pair options do not affect character-password mode.

### Password length planner

The random-character mode now includes an **entropy-target planner** (64, 80, 128, 192 or 256 bits). It searches the allowed 12–64 character lengths using `calculatePasswordEntropy()` with the currently selected alphabet, look-alike exclusion and per-group requirement. The result is the **shortest length that meets the chosen mathematical target**, or an explicit unavailable result if the target cannot be met within 64 characters. Selecting **Use suggested length** updates the password-length slider and invalidates an already generated secret; it does **not** silently regenerate or persist a secret.

Library callers can use `minimumPasswordLength({ lower: true, upper: true, numbers: true, special: true, requireEach: true }, 128)`. A numerical entropy target does not guarantee that a password will survive phishing, an online attack, compromised devices or unfavorable account policies.

## Features

- 4–12 independent adjective–noun pairs, default 6.
- Separate random-character password generator (12–64 characters) with selectable character sets and exact entropy based on the resulting alphabet.
- Optional exclusion of seven visually ambiguous characters; the library takes `excludeAmbiguous: true` in `createRandomPassword()` or `calculatePasswordEntropy()`.
- Hyphen, space, underscore and period separators.
- Optional uniformly selected digit and symbol.
- Honest entropy calculation and source-code-readable word lists.
- Copy button with warning about clipboard persistence, and an explicit **Clear** action that drops the generated secret from the app's active state. A successful copy immediately conceals the secret on screen; overlapping clicks are disabled while the clipboard write is pending. Stale asynchronous writes cannot reenable a cleared secret, and the interface warns when an old copied secret may remain on the clipboard. Clearing does not clear OS clipboard managers, browser heap snapshots or saved exports.
- Conceal/reveal on-screen display; the visible secret automatically hides after a successful copy, after 30 seconds, when the tab becomes hidden, or when the browser window loses focus. Revealing it starts a fresh 30-second display period. Concealment does not delete the secret from memory or clear the clipboard; use **Clear** to remove it from the app's active state.
- No password data written to browser storage, query strings, network endpoints or logs.
- Responsive browser interface, plain-language explanations, and MIT license.

## API

The implementation is a browser ES module:

    import { createPassphrase, calculateEntropy, minimumPassphrasePairs, minimumPassphrasePairsWithinLimit, passphraseLengthFit, passphraseLengthBounds, createRandomPassword, calculatePasswordEntropy, minimumPasswordLength } from './src/generator.js';
    const result = createPassphrase({ pairs: 6, separator: '-', digit: false, symbol: false });
    const random = createRandomPassword({ length: 20, lower: true, upper: true, numbers: true, special: true });
    const readable = createRandomPassword({ length: 24, excludeAmbiguous: true });
    const minLength128 = minimumPasswordLength({ lower: true, upper: true, numbers: true, special: true }, 128);
    const minPairs80 = minimumPassphrasePairs({ digit: false, symbol: false }, 80);
    const wordPairLengths = passphraseLengthBounds({ pairs: 6, separator: '-' });
    const accountFit = passphraseLengthFit({ pairs: 6, separator: '-' }, 64);
    const guaranteedPairs = minimumPassphrasePairsWithinLimit({ separator: '-' }, 80, 64);
    const strict = createPassphrase({ pairs: 6, maxCharacters: 96 }); // Throws if worst-case output would not fit.

`result.phrase` and `random.password` are secrets and should never be logged or persisted by default. The returned `bits` estimates describe the generator’s actual random choices.

## Security considerations

- Generate passphrases only on a trusted device in a trusted browser.
- Never reuse passphrases between accounts. Consider a reputable password manager for storage.
- Clipboard managers and installed applications may retain copied secrets; clear the clipboard when appropriate.
- Auto-conceal reduces accidental on-screen exposure, but does not make the underlying JavaScript memory secret or protect the device from a malicious extension.
- Website compromise or a malicious browser extension could access the displayed passphrase. Local-only operation is not protection against compromised devices.
- The code is not independently security-audited. **Automated tests have not yet been run**; the owner plans centralized testing before treating it as production-ready.

## Structure

- `src/generator.js` — audited-in-principle random-choice algorithm, word lists and entropy calculation (not independently audited).
- `index.html`, `styles.css`, `app.js` — standalone generator interface.
- `LICENSE` — MIT.

## Author

Built by Meir Dvir · https://github.com/MeiRR17

If a clipboard write finishes after the secret is regenerated or cleared, the interface warns that the clipboard may still contain the previous secret. Browser clipboard operations cannot be reliably revoked once issued.
