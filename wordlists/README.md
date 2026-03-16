# Wordlist Layout

This directory keeps two compatible layouts:

- Flat files in `wordlists/` for legacy/manual usage.
- Tiered files in `wordlists/discovery`, `wordlists/verify`, and `wordlists/aggressive` for future mode-aware loading.

Suggested mapping:

- `discovery/`: low-risk path and parameter enumeration.
- `verify/`: confirmation payloads with bounded noise.
- `aggressive/`: deeper or bypass-oriented payloads that are more expensive or noisier.
