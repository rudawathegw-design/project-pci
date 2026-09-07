# project-pci

PCI DSS Compliance Cockpit for First Iraq Bank — a private, password-gated
dashboard published via GitHub Pages (`docs/`).

- **Data is encrypted at rest** (AES-256-GCM, key derived by PBKDF2-SHA256 from
  the site password). The published page ships only ciphertext; it is decrypted
  in the browser after the password is entered. The repo/Pages never expose raw
  PCI findings.
- `tools/import_pci.py` — turns the assessment gap report + project plan
  spreadsheets into `data/pci_data.json`.
- `tools/build_pci.py` — encrypts that data and renders `docs/index.html`.
- Live FIBXPI status + commenting are served at runtime by the Worker in
  `worker/` (Jira token stays server-side).

Rebuild after updating data:  `python tools/build_pci.py`
