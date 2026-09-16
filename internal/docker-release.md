![Logo](images/sweden-connect.png)

# Building a Release Docker Image

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

Every push to `main` triggers a GitHub Actions workflow that builds and publishes a **snapshot** Docker image to the
GitHub Container Registry (`ghcr.io`). This image always carries whatever version is currently set in `pom.xml`
(for example `1.0.9-SNAPSHOT`).

To publish a **versioned release** image, push a git tag matching `v<version>`, for example:

```bash
git tag v0.0.3
git push origin v0.0.3
```

Pushing a tag of the form `v*` triggers the release workflow, which:

1. Sets the Maven project version to the tag name with the leading `v` stripped (`v0.0.3` &rarr; `0.0.3`).
2. Builds the application and publishes a Docker image to `ghcr.io` tagged with that version.

The tag name must start with `v` (e.g. `v1.2.0`, `v0.0.3-rc1`) — tags that do not match this pattern will not
trigger a release build.

-----

Copyright &copy; 2025-2026, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
