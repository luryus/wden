# Changelog

## next

## 0.10.2

- Fixed Argon2 not working with Bitwarden servers

## 0.10.1

- Dependency crate updates, including some security fixes

## 0.10.0

- Enabled LTO and debug symbol stripping in release builds
- Changed CI to build Linux binaries on Ubuntu 22.04. The prebuilt Linux binaries are now linked against OpenSSL 3. They should now work on recent versions of most Linux distros.
- Dependency crate updates

## 0.9.1

- Dependency crate updates

## 0.9.0

- Added Wayland clipboard support on Linux (#38)
- Dependency crate updates

## 0.8.1

- Fixed collection list not being scrollable (#224)

## 0.8.0

#### Server configuration changes
Wden now supports easier Bitwarden cloud server configuration. The new flag `--bitwarden-cloud-region <region>` should now be used instead of the `vault.bitwarden.com` server URL.

#### All changes

- Add support for configuring separate API and identity server urls (#221)
- Make selecting Bitwarden US/EU region servers easier (#221)
- Pretty-print profile list as a table using [tabled](https://crates.io/crates/tabled/) (#221)
- Change configuration file format (support the separate API/identity URLs), automatically migrate files into the new format (#221)
- Dependency crate updates

## 0.7.1

- Fix prelogin failing with Vaultwarden
- Dependency crate updates for security fixes

## 0.7.0

- Zeroize password after login form submit (wipe it from memory)
- Add support for Argon2 KDF (#147)
- Dependency crate updates

## 0.6.0

- Dependency crate updates
- Search field is now cleared when it's focused with `/`

## 0.5.0

- Add `--allow-invalid-certs` option for allowing connections with invalid and untrusted certificates.
- Add support for bypassing CAPTCHA checks with personal api keys
- Fix vault loading failing if user name is not set in the profile details
- Add a hidden option `--always-refresh-token-on-sync` for making testing easier

## 0.4.0

- Collection filtering support
- New theme (UI colors)
- Upgrade all RustCrypto crates
- Other crate updates (and Github dependabot integration helping with future updates)
- Support showing identity item details
- Enable gzip in http requests
- A lot of internal refactoring

## 0.3.1

- Fix first row being hidden after unlocking (#8)
- Fix org emoji not shown with all terminal widths (#9)

## 0.3.0

- Added version flag (#11)

## 0.2.0

- Initial (versioned) release
