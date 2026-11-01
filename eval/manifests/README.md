# Manifests

Evaluation pairs: metadata and hashes only, never payload bytes. See `.claude/rules/samples.md`.
Check them with `just validate-manifests`. The schema is `eval/src/drift_eval/manifest.py`.

| File | Holds | `case_type` |
|---|---|---|
| `positives.yaml` | Real malicious updates, paired with the last benign version | `update_compromise`, `dependency_injection`, `ci_pipeline`, `destructive`, `new_malicious_package` |
| `hard_negatives.yaml` | Legitimate updates that add scary-looking capabilities | `hard_negative` |
| `routine.yaml` | Ordinary consecutive versions of popular packages | `routine` |
| `synthetic.yaml` (optional) | Technique fixtures from `fixtures/` | `synthetic` |

## Fields

| Field | Meaning |
|---|---|
| `ecosystem` | `npm`, `pypi` or `crates` |
| `package` | Package name |
| `benign_version` | Quote it. Unset only for `new_malicious_package` |
| `target_version` | Quote it. YAML reads an unquoted `1.10` as the number 1.1, which the validator rejects |
| `case_type` | See the table above |
| `payload_context` | `install`, `import` or `call`. Positives and synthetic only |
| `techniques` | Any of `exfil`, `dropper`, `miner`, `wallet`, `worm`. May be empty only for `destructive` |
| `provenance_present` | `y` or `n`. Leave unset if no source establishes it (negatives must set it) |
| `incident_date` | `YYYY-MM-DD`. Required for real positives |
| `source_urls` | https URLs. Required for real positives and hard negatives |
| `benign_tarball`, `target_tarball` | Expected hashes, described below |
| `sample_available` | `y` or `n`. `y` needs a `target_tarball` hash to verify the sample against |
| `traits` | Hard negatives only: what looks scary (see `Trait` in the schema) |
| `rationale` | Hard negatives only: why this is legitimate |
| `notes` | Optional. At most 500 characters, like all free text, and no long encoded strings |

## Hashes

```yaml
target_tarball:
  sha512: <lowercase hex>   # any of sha1, sha256, sha512
  source: https://...       # the page that states the hash
```

Record only a hash that the cited source states, and never one computed from a sample. npm's `dist.integrity` is
base64, so convert it to hex. `sha1` is included because npm's `shasum` and many advisories only give that. With no
hash, say why:

```yaml
target_tarball:
  note: No cited source states a hash for this version.
```

Across all files, the validator also rejects a repeated pair, and a version listed as malicious in `positives.yaml`
appearing on the benign side of any pair, or as the target of a negative.
