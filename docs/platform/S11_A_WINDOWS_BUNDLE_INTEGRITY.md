# S11-A — Windows Offline Bundle Integrity Verification

## Purpose

S11-A starts the post-S10 enterprise lifecycle work by adding an independent
verification step for the Windows offline deployment bundle produced by S10E.

S10E already creates:

- `AegisGuard-Windows-Enterprise.zip`
- `manifest.json`
- `SHA256SUMS.txt`

S11-A verifies that release material still matches those records before it is
accepted for deployment or transfer.

## Command

```text
python scripts/verify_windows_offline_bundle.py <bundle-path>
```

The verifier accepts:

- the generated ZIP archive;
- the extracted `AegisGuard-Windows-Enterprise` directory;
- a parent directory containing that bundle directory.

Successful verification reports:

```text
BUNDLE_VERIFICATION = PASS
SOURCE_COMMIT = ...
SOURCE_DIRTY = False
PAYLOAD_FILE_COUNT = ...
CHECKSUMMED_FILE_COUNT = ...
ARCHIVE_SHA256 = ...
```

## Verification contract

S11-A rejects a bundle when any of these conditions occur:

- archive path traversal or unsafe ZIP entry names;
- ZIP symlink entries;
- missing `manifest.json`;
- missing `SHA256SUMS.txt`;
- malformed or duplicate checksum records;
- missing or extra files relative to checksum coverage;
- SHA-256 mismatch;
- manifest payload size mismatch;
- manifest payload SHA-256 mismatch;
- manifest payload coverage mismatch;
- unsupported manifest schema/product/platform/bundle identity;
- unsafe manifest paths;
- dirty-source release by default;
- any S10E security flag indicating bundled runtime databases, private keys,
  certificates, customer logs, or Python source.

`--allow-dirty-source` exists only for explicit validation/development use and
must not be used as a production release-acceptance default.

## Security boundary

S11-A provides corruption/tamper detection against the bundle's own S10E
manifest and checksum records.

It does **not** establish publisher authenticity because the checksums and
manifest are stored with the bundle and are not yet externally signed.

A future release-signing stage must bind release metadata to a trusted signing
identity rather than treating embedded SHA-256 values as a digital signature.

## Scope unchanged

S11-A does not modify:

- Analyzer runtime behavior;
- Collector runtime behavior;
- S3 collector authentication or mTLS;
- S7 privacy/evidence controls;
- S8 response governance;
- S9 operational visibility;
- S10 installation/runtime ownership;
- database schemas.

## Validation gate

```text
python -m pytest tests/deployment/test_s11a_windows_bundle_integrity.py -q
python -m pytest tests/deployment -q
python -m pytest tests/platform -q
python -m pytest tests/intelligence -q
python -m pytest tests/frontend -q
python -m pytest backend/collector/test_live_monitoring.py -q
python -m pytest backend/analyzer/test -q
git diff --check
```

S11-A is complete when the focused and regression gates pass and the change is
merged into `product/integration`.
