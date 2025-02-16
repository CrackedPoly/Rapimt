# Contributing to Rapimt
❤️️ Thank you for considering contributing to Rapimt!

## Contributing in issues

## Contributing in Pull Requests

## Code format

Format is as defined in the `.rustfmt.toml` file. Before committing, run `cargo
fmt --all --check` to reveal any formatting inconsistencies. Run `cargo fmt
--all` to format your code locally.

## Branching

Any feature or bug fix should be developed in a separate branch. Once the
feature is ready, it should be reviewed and merged into the `dev` branch. The
`dev` branched is timely merged into the `main` branch and versioned as a new
release.

## Versioning

Patch (_._.x) releases should only contain bug fixes or documentation changes.
Besides this, these releases should not substantially change runtime behavior.

Minor (_.x) releases may contain new functionality, MSRV increases (see above),
minor dependency updates, deprecations, and larger internal implementation
changes.

This is as defined by [Semantic Versioning 2.0](https://semver.org/).
