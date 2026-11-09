# drift-fixture-evil-dep (SYNTHETIC)

**Synthetic test fixture. Not real malware and not a real package.**

The dependency `drift-fixture-dep-inject` 1.0.1 adds. Its only version has a `postinstall` hook running `setup.js`,
which recreates the install-time behavior of injected-dependency payloads: it reads `~/.npmrc` (only its length is kept),
runs `uname`, and looks up a name under the sinkhole, `sinkhole.invalid`, to report both. Nothing leaves the sandbox.
