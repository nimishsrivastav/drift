# drift-fixture-benign (SYNTHETIC)

**Synthetic test fixture. Not a real package.**

A routine update that must produce no capability findings. 1.0.0 already fetches over HTTPS inside a function (call
time). 1.0.1 moves formatting into a new pure module, `lib/format.js`, and loads it from the entry point; the HTTPS use
is unchanged. Only low-confidence file changes are expected.
