# Release process

1. Prepare changes for the new release
  - update version number in `Cargo.toml` and `Cargo.lock`
  - update `CHANGELOG.md`: move entries under "next" to a new heading with the new version number
    * The heading must contain only the version number, as the file is later parsed to generate release notes in the GitHub release
2. Commit these changes to `main`
3. Create a tag for the version bump commit. The tag name must be the version number without any prefixes. E.g.
    ```
    git tag 1.2.3
    ```
4. Push the main branch and the tag.
5. If all goes as planned, GitHub Actions will build the release binaries and create the release in GitHub.