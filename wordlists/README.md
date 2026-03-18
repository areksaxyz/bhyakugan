# Wordlist Layout

This directory keeps two compatible layouts:

- Flat files in `wordlists/` for legacy/manual usage.
- Tiered files in `wordlists/discovery`, `wordlists/verify`, and `wordlists/aggressive` for mode-aware loading.

Suggested mapping:

- `discovery/`: low-risk path and parameter enumeration.
- `verify/`: confirmation payloads with bounded noise.
- `aggressive/`: deeper or bypass-oriented payloads that are more expensive or noisier.

Currently wired automatically when the local `wordlists/` directory is available:

- `discovery/paths-*.txt` into the directories plugin.
- `discovery/graphql-endpoints.txt` into GraphQL discovery.
- `discovery/openredirect-params.txt` and `discovery/ssrf-params.txt` into parameter discovery.
- `verify/upload-safe-filenames.txt` and `verify/upload-safe-content-types.txt` into default upload probes.
- `aggressive/upload-bypass-filenames.txt` into extra upload probes for `aggressive` / `lab` mode.

Some files remain staged corpus only and are not yet consumed automatically by every plugin.
