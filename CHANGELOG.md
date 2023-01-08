# Changelog

## next

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
