# Passphrase Forge

Create memorable random passphrases in a modern browser using **cryptographically secure randomness**. No signup, network service, analytics, storage of generated phrases, or third-party dependencies.

## Get started

Serve the repository root using a local HTTP server (required for browser ES modules):

    python3 -m http.server 8000

Visit http://localhost:8000, select the number of word pairs, separator, and optional digit/symbol; then press **Generate passphrase**. The application also works on static HTTPS hosting. Web Crypto must be available (HTTPS or localhost). If secure randomness is unavailable, generation stops rather than falling back to predictable randomness.

## How it works

Each pair is a randomly chosen adjective followed by a randomly chosen noun. The generator uses two curated 64-word lists, creating 4,096 possible adjective–noun combinations per pair. For example, a *sample-shaped* phrase could look like `quiet-lantern-bright-river`; never use an example string as a real secret.

Every list index is selected independently with `crypto.getRandomValues()` and rejection sampling to avoid modulo bias. The generator never uses `Math.random()`. List sizes are checked for duplicate entries.

**Random-choice entropy**, not a password “quality score,” is reported. With six independent pairs, the entropy is 6 × log2(4,096) = **72 bits**, assuming unpredictable generation and the full list available to an attacker. Adding a random digit gives log2(10) extra bits; one uniformly selected symbol from eight choices adds 3 more bits. Separators do **not** add entropy.

Passphrase length and entropy are calculated from actual generator choices; the result is not a claim of immunity to guessing, phishing, malware, breaches, or password-reuse attacks.

## Features

- 4–12 independent adjective–noun pairs, default 6.
- Hyphen, space, underscore and period separators.
- Optional uniformly selected digit and symbol.
- Honest entropy calculation and source-code-readable word lists.
- Copy button with warning about clipboard persistence.
- Conceal/reveal on-screen display; automatically conceals when the tab becomes hidden.
- No password data written to browser storage, query strings, network endpoints or logs.
- Responsive browser interface, plain-language explanations, and MIT license.

## API

The implementation is a browser ES module:

    import { createPassphrase, calculateEntropy } from './src/generator.js';
    const result = createPassphrase({ pairs: 6, separator: '-', digit: false, symbol: false });

`result.phrase` is the secret and should never be logged or persisted by default. The returned `bits` estimate describes the generator’s random choices.

## Security considerations

- Generate passphrases only on a trusted device in a trusted browser.
- Never reuse passphrases between accounts. Consider a reputable password manager for storage.
- Clipboard managers and installed applications may retain copied secrets; clear the clipboard when appropriate.
- Website compromise or a malicious browser extension could access the displayed passphrase. Local-only operation is not protection against compromised devices.
- The code is not independently security-audited. **Automated tests have not yet been run**; the owner plans centralized testing before treating it as production-ready.

## Structure

- `src/generator.js` — audited-in-principle random-choice algorithm, word lists and entropy calculation (not independently audited).
- `index.html`, `styles.css`, `app.js` — standalone generator interface.
- `LICENSE` — MIT.

## Author

Built by Meir Dvir · https://github.com/MeiRR17
