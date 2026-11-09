# drift-fixture-install-hook (SYNTHETIC)

**Synthetic test fixture. Not real malware and not a real package.**

1.0.0 is benign. 1.0.1 recreates the technique of the eslint-scope 3.7.2 compromise: the update adds a `postinstall`
hook that runs a new file, `lib/build.js`, which reads `~/.npmrc` and reports to a remote host. Here the host is only
the sinkhole, `sinkhole.invalid`, and only the length of the file is sent, never its contents. `lib/build.js` is absent
from `repo/`, as it was from the real project's repository.
