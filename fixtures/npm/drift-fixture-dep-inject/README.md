# drift-fixture-dep-inject (SYNTHETIC)

**Synthetic test fixture. Not real malware and not a real package.**

1.0.0 is benign. 1.0.1 recreates the technique of the axios → plain-crypto-js and event-stream → flatmap-stream
compromises: the update changes no code of its own, but adds a dependency, `drift-fixture-evil-dep`, whose install
hook carries the payload. The dependency is never even required; installing it is enough. drift reports the new
dependency, analyzes it on its own, and rolls its install-time findings up into this package's report.
