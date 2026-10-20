# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's "Report a vulnerability" (Security tab) for this repository, rather than a public issue. Include the version, steps to reproduce, and impact. Please do not attach real vehicle logs; a synthetic reproduction is enough.

## Deployment guidance

CAN Log Analyzer processes files that may contain sensitive vehicle data.

* The default bind address is `127.0.0.1`. Before exposing it, put it behind a TLS-terminating reverse proxy and set `CAN_ANALYZER_TOKEN`. The token is a single shared secret, not per-user access control.
* Analyses are stored unencrypted under `CAN_ANALYZER_DATA_DIR`. Protect that directory, and delete analyses you no longer need.
* Upload, frame-count, time and concurrency limits are on by default; see the README for the variables.

## Built-in protections

Streaming upload limits (checked as bytes arrive), fixed server-side file names, strict analysis-ID validation, parameterised SQL only, generic 500 responses without stack traces, CSV formula-injection neutralisation, HTML-escaped reports, a restrictive Content-Security-Policy, and no third-party requests from the UI.

## Known limits

* The frame and time limits are cooperative: a DBC that makes the third-party parser run very long is bounded only by the DBC size limit.
* No rate limiting per client; use your reverse proxy.
* Log-format parsers (python-can) and the DBC parser (cantools) are third-party code. Dependencies are version-bounded and scanned with `pip-audit` in CI.
