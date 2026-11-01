# drift

Capability-drift detection for open source package updates.

drift flags malicious **updates** to legitimate packages by diffing what a new version can do and actually does
against its predecessor, weighted by when that code runs (install-time > import-time > call-time).

**Status: early development.** Nothing works end to end yet. See [PLAN.md](PLAN.md) for milestones.

## Development

```sh
./check-prereqs.sh   # verify the toolchain; read-only
```

Design decisions are recorded in [docs/DECISIONS.md](docs/DECISIONS.md).

## License

[Apache-2.0](LICENSE)
