![Logo](../docs/images/sweden-connect.png)

# Building a Release Docker Image

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

Every push to `main` triggers a GitHub Actions workflow that builds and publishes a **snapshot** Docker image to the
GitHub Container Registry (`ghcr.io`), tagged with the version in `pom.xml` (for example `1.0.9-SNAPSHOT`). When
`pom.xml` holds a release version (no `-SNAPSHOT` suffix), nothing is published, so a release image is never
overwritten.

To publish a **versioned release** image:

1. Set the release version in `pom.xml`, e.g. `1.0.9`, and get the change onto `main`.
2. Push a git tag named `v` followed by that version:

   ```bash
   git tag v1.0.9
   git push origin v1.0.9
   ```

3. Set the next snapshot version in `pom.xml`, e.g. `1.0.10-SNAPSHOT`.

Pushing a tag of the form `v*` triggers the Docker release workflow (`docker-release.yml`), which:

1. Checks that the tag matches the version in `pom.xml` (`v1.0.9` &harr; `1.0.9`) and that the version is not a
   snapshot. Otherwise the workflow fails and nothing is published.
2. Builds the application and publishes a Docker image to `ghcr.io` tagged with the version and with `latest`.

A GitHub release pointing to the release notes is also created for the tag.

The tag name must start with `v` — tags that do not match this pattern will not trigger a release build.

-----

Copyright &copy; 2025-2026, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
