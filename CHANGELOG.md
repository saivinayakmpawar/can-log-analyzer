# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/). Versions follow [SemVer](https://semver.org/).

## [0.2.0]

### Added
- Dashboard rebuilt: drag-and-drop upload, overview, fault list with severity and classification filters, fault investigation drawer (evidence, detection method, zoomed signal plot, related frames, hypotheses), paged/sortable/searchable frame viewer, signal viewer with drag-to-zoom, pan and time-range selection, message and ECU overview, DBC browser, log comparison, analysis history, report downloads, loading/empty/error states.
- Frame store (SQLite) so the frame viewer, signal zoom and correlation read from disk instead of memory.
- Diagnostic rules file (JSON): extra thresholds, per-message cycle/tolerance/required, rolling counters, checksums. Strict validation with clear errors.
- New checks: rolling-counter validation, checksum validation (`xor8`, `sum8`, `crc8`, `crc8_sae_j1850`, plugin registry), frequency deviation, timestamp regression, malformed/skipped log lines (`.asc`, `.log`), empty log.
- Findings now carry `classification` (confirmed rule violation vs observed anomaly), `evidence`, `method`, `possible_causes` (hypotheses), stable IDs and `end_time`.
- Bus load: documented assumptions, worst-case (max stuffing) upper bound, remote frames counted for load, CAN FD frames reported and excluded.
- Per-signal statistics and least-squares trend; Pearson correlation endpoint; log comparison endpoint.
- Reports: HTML, PDF and CSV (findings and message timing), reproducible from the stored analysis.
- Optional API token; security headers and a strict CSP; resource limits for upload size, frames, time and concurrency.
- Synthetic `ev_advanced` sample set (29-bit ID sharing a number with an 11-bit ID, multiplexing, counter, CRC-8, injected faults, clean twin log, rules file).
- `python -m app`, `docker-compose.yml`, CI workflow (tests on 3.10 to 3.13, ruff, mypy, pip-audit, Docker build), issue/PR templates, SECURITY.md, CONTRIBUTING.md, architecture docs.
- 119 new tests.

### Fixed
- **11-bit and 29-bit identifiers with the same number were treated as one message**, so an extended-ID frame could be decoded as an unrelated standard message.
- **Multiplexed messages crashed the analysis** (`KeyError` for inactive multiplexed signals).
- **Backwards timestamps went unreported.**
- **Lines skipped by the log parser were silent** (now reported for `.asc` and `.log`).
- Uploads were read fully before the size limit applied; limits are now enforced while streaming, and per file.
- Client file names are never used as paths; analysis IDs are strictly validated; internal errors no longer leak details.
- The demo log generator wrote one frame 3 ms ahead of its neighbours, so `ev_demo.asc` had out-of-order timestamps. The generator now sorts by time; `ev_demo.asc` contains the same frames, in chronological order.
- README claimed CI and a `.gitignore` that were not in the repository; both now exist.

### Changed (behaviour differences to be aware of)
- A `decode_error` is now one finding per message with a frame count (was one per bad frame).
- An empty log reports a single `empty_log` finding instead of one `missing_message` per DBC message.
- Unknown extended IDs are labelled `0x... (ext)`.
- Message rows gained `extended`, `senders`, `expected_source`, `max_gap_ms`; `summary` gained several counters. Existing keys keep their meaning.
- Signal series are reduced with a min/max-preserving reducer so short spikes stay visible.
- The UI no longer loads Chart.js or fonts from a CDN; Chart.js is vendored (MIT licence included).
- Old UI screenshots in `docs/` were replaced by screenshots of the new UI.
