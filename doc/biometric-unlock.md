# Biometric Unlock (Experimental)

wden supports unlocking a locked vault using biometric authentication (e.g. fingerprint) instead
of re-entering the master password. This feature is *experimental* and is supported on Linux and
Windows.

## Enabling

Biometric unlock is disabled by default and must be enabled manually in the profile config file.

The profile config is at `~/.config/wden/<profile-name>.json`. Open it in a text editor and set:

```json
"experimental_unlock_with_biometrics": true
```

Make sure wden is not running when you edit the file. The setting takes effect on the next launch.

## Linux Setup

Biometric authentication on Linux goes through PAM that needs to be set up for fprintd
fingerprint support. Follow your distro's documentation for how to do that.
wden uses the PAM service named `wden`, which means you need to create `/etc/pam.d/wden` with an appropriate configuration:

```
#%PAM-1.0
auth       required     pam_fprintd.so
account    required     pam_permit.so
```

wden checks for the existence of `/etc/pam.d/wden` at startup to decide whether to offer the
biometric unlock option. If the file is missing, the button will not appear even if the feature
is enabled in the config.

## Windows Setup

On Windows, biometric authentication uses Windows Hello. To use it, Windows Hello must be
configured in Windows Settings (Settings > Accounts > Sign-in options) with at least one
biometric method (fingerprint or facial recognition) or a PIN.

No additional application-level configuration is needed beyond enabling the feature in the
profile config. wden checks Windows Hello availability at startup and only offers the biometric
unlock option if it is available.

Windows Hello supports fingerprint, facial recognition, and PIN as authentication methods.
The system will present its standard authentication dialog when biometric unlock is requested.

## Security Caveats

When biometric unlock is enabled and the vault is locked, wden keeps the vault decryption key
available so it can be recovered without the master password. This has an important security
implication compared to password-only unlock:

- **With password unlock**, wden attempts to clear all unencrypted key material from memory when
  the vault is locked. An attacker cannot easily recover the key from a locked wden process.

- **With biometric unlock**, the decryption key is intentionally kept accessible while the vault
  is locked. The storage mechanism is platform-specific:

  - **Linux**: The key is stored in the **kernel keyring**. A **root-level attacker** (or an
    attacker with access to the kernel keyring of your session, e.g. via a compromised system
    service) could potentially extract the key without passing biometric authentication.

  - **Windows**: The key is stored in process memory, encrypted with **DPAPI** (Windows Data
    Protection API) which is scoped to the current user account. An attacker with access to the
    process memory **and** the ability to run code as the same user could decrypt the key without
    passing biometric authentication.
