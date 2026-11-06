> **Retired preview, not maintained.**

# `receipts-verify-action` & `hvr-pre-commit`

SPDX-License-Identifier: Apache-2.0

GitHub Action and Git `pre-commit` hook for deterministic, offline Class-1 verification of Hivemind Receipts (`.hvr`), C2SP `tlog-checkpoint` witness cosignature quorums (3-of-5), and DSSE/SLSA v1.0 provenance envelopes.

## GitHub Actions Usage

> Publishing target organization is bound in `conformance/receipts/publishing-targets.json` (`[OWNER]`).

```yaml
- name: Verify Agent Action Receipts (.hvr)
  uses: ./packages/receipts-verify-action
  with:
    receipts-path: './receipts'
    trust-file: './trust-roots.json'
    checkpoint-file: './checkpoint.note'
    min-witness-quorum: '3'
```

## Git `pre-commit` Hook Usage

Add to `.pre-commit-config.yaml` (replace `<GITHUB_ORG>` from `conformance/receipts/publishing-targets.json` once published):

```yaml
repos:
  - repo: https://github.com/<GITHUB_ORG>/receipts-verify-action
    rev: v0.1.0
    hooks:
      - id: hvr-verify-receipts
```
