# Changelog

Semua perubahan penting untuk repo ini dicatat di file ini.

## v4.0.0 - 2026-03-18

### Positioning

Rilis ini memposisikan Bhyakugan sebagai scanner untuk:

- unauthenticated public exposure
- sensitive artifact discovery
- recon intelligence

Fokus utamanya bukan lagi scanner eksploitasi login/auth-heavy.

### Runtime dan default behavior

- Runtime mode dibakukan menjadi `public`, `extended`, dan `research`.
- Default CLI sekarang `public`.
- Alias lama tetap diterima: `strict`, `balanced`, `aggressive`, `bounty`, `lab`.
- Auto endpoint cap mengikuti mode, sehingga `-max-endpoints=0` tidak lagi berarti unlimited.

### Reporting model

- HTML report dipisah menjadi tiga bucket utama:
  - `Validated Public Exposures`
  - `Probable Sensitive Signals`
  - `Recon / Attack Surface`
- Dashboard atas sekarang memisahkan overview exposure/signal/recon dari severity validated findings.
- Severity utama hanya dihitung untuk validated exposure.
- `Unique Exploitable` / validated scope counter tidak lagi bentrok dengan label finding.
- Recon seperti login form, path discovery, dan sourcemap tidak lagi tampil seperti vulnerability utama.

### Verification dan classification hardening

- Weak boolean differential tanpa bukti body/structure yang kuat tidak lagi naik menjadi `CONFIRMED`.
- XPath informational signal tidak lagi bisa tampil kontradiktif sebagai finding confirmed.
- IDOR didemote menjadi `Object Reference Surface`, bukan headline vulnerability.
- Confidence dan bucket sekarang memakai status canonical lintas plugin, scanner, dan renderer.

### Wordlist dan plugin wiring

- Corpus lokal exposure-first di `wordlists/` mulai di-wire ke plugin yang paling aman dan paling relevan:
  - `directories`
  - `graphql`
  - `jsanalyzer`
  - `public_storage`
- README dan layout corpus repo diselaraskan dengan wiring yang benar-benar aktif.

### Guardrail tests

- Report-level regression untuk mencegah kontradiksi `CONFIRMED` vs signal-only.
- Golden-file HTML regression untuk section heading, counter, dan bucket layout.
- Runtime mode tests untuk memastikan `public` tidak menyalakan plugin research-only.
- Plugin regression untuk XPath trap exact-path, SSTI arithmetic verification, dan wiring corpus exposure-first.
- Localhost fullstack regression terhadap `cmd/mockserver` sekarang lulus kembali.

### Release hygiene

- README, banner binary, module path, dan minimum Go version sudah selaras.
- Build target resmi didokumentasikan sebagai `./cmd/bhyakugan`.
- Root repo dibersihkan dari artefak lokal yang tidak layak dibawa sebagai state rilis.

### Recommended release tag

Tag release yang disarankan untuk fase ini adalah `v4.0.0`.

Karena worktree bisa berada dalam keadaan dirty saat pengembangan berlangsung, tag sebaiknya dibuat hanya setelah perubahan fase ini di-commit. Contoh:

```bash
git tag -a v4.0.0 -m "Bhyakugan v4.0.0"
git push origin v4.0.0
```
