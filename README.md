# drift

Capability-drift detection for open source package updates.

drift flags malicious **updates** to legitimate packages by diffing what a new version can do and actually does
against its predecessor, weighted by when that code runs (install-time > import-time > call-time).

**Status: early development.** drift cannot analyze a package yet: the services start and identify themselves, but
analysis is not implemented. See [PLAN.md](PLAN.md) for milestones.

## Development

```sh
./check-prereqs.sh                # verify the toolchain; read-only
just gen build test lint          # regenerate stubs, then build, test and lint everything
just up                           # build and start all services
just logs                         # the orchestrator's log, including each analyzer's Info
just down
```

Design decisions are recorded in [docs/DECISIONS.md](docs/DECISIONS.md).

## License

[Apache-2.0](LICENSE)
