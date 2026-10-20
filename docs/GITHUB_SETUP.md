# GitHub repository settings

These live outside the code, so apply them once in the repository settings (or with the GitHub CLI).

**Description**

> An open-source automotive CAN bus analysis and diagnostics platform featuring DBC decoding, signal visualization, anomaly detection, log comparison, and engineering reports.

**Topics:** `can-bus`, `automotive`, `ev`, `dbc`, `python`, `vehicle-networking`, `diagnostics`

```bash
gh repo edit --description "An open-source automotive CAN bus analysis and diagnostics platform featuring DBC decoding, signal visualization, anomaly detection, log comparison, and engineering reports." \
  --add-topic can-bus --add-topic automotive --add-topic ev --add-topic dbc --add-topic python \
  --add-topic vehicle-networking --add-topic diagnostics
```

**Social preview:** upload a PNG export of `docs/banner.svg` (Settings, General, Social preview).

**Recommended:** enable private vulnerability reporting (Settings, Code security) so the link in `SECURITY.md` works, and require the `test` CI job on `main`.
