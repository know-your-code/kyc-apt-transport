# Security model

## Trust anchor — GPG signing key

The kyc apt repository's `Release` / `InRelease` files are signed by
a GPG primary key whose public fingerprint is published below. Users
are encouraged to verify this against the keyring served at
`https://apt.knowyourco.de/install/kyc-keyring.gpg` before trusting
the apt source.

**Primary key fingerprint:**

```
74CF D412 63CD 5132 633B  A828 4CEB 4F38 3449 6AEB
```

(Or with no spaces: `74CFD41263CD5132633BA8284CEB4F3834496AEB`.)

**Key details:**
- Algorithm: Ed25519
- Capability: Certify-only
- Generated: 2026-05-13
- Expiry: none

**Signing subkey (for CI use):**
- Fingerprint: `8F23 8A92 2D58 EA27 809A  C277 4582 13F2 E07C FB1E`
- Algorithm: Ed25519
- Capability: Sign-only
- Expiry: 2028-05-12 (rotation required)

You can verify the fingerprint of an installed keyring with:

```sh
gpg --show-keys --with-fingerprint --with-colons \
  /usr/share/keyrings/kyc-keyring.gpg \
  | awk -F: '/^fpr:/ { print $10; exit }'
```

## Key hierarchy

```
primary (ed25519, no expiry)           OFFLINE
  ├── certify subkey                   rarely used; only when issuing
  │                                    new signing subkeys
  └── signing subkey (ed25519, 2y)     EXPORTED to GH Actions
                                       (symmetric-encrypted)
                                       used to sign Release in CI
```

The primary key never touches a networked filesystem. It lives on
two YubiKey hardware tokens (one daily-carry, one in a safe). The
signing subkey is exported once during the ceremony, symmetric-
encrypted with a separate passphrase, base64-encoded, and stored as
a GitHub Actions secret (`APT_SIGNING_SUBKEY_ASC_BASE64`). CI
imports it into an ephemeral `$GNUPGHOME` (tmpfs), signs, then
cleans up.

A revocation certificate for the primary key was pre-generated
during the ceremony and is stored alongside the YubiKeys in
hardcopy form. It is never uploaded online.

## What's licensed and what isn't

| Path | Auth | Why |
|------|------|-----|
| `/install/*` | none | Bootstrap downloads: the public GPG keyring, the apt-transport-kyc package itself. Anyone with the install URL gets these. |
| `/dists/*` | none | apt repo metadata (`Release`, `InRelease`, `Packages`). The metadata is GPG-signed; tampering is detected by every client. |
| `/pool/*.deb` | `Authorization: Kyc-License <base64>` | The actual kyc binaries. License file is the bearer credential; the worker Ed25519-verifies it offline. |

## Compromise procedures

**If the signing subkey is suspected compromised:**

1. From the air-gapped machine (YubiKey reinserted, USB stick
   mounted): `gpg --edit-key <fpr>` → select the subkey → `revkey`
   → `save`.
2. Export the updated public key. Push to R2:
   `aws s3 cp kyc-keyring.gpg s3://kyc-releases/apt/install/...`.
3. Generate a new signing subkey from the offline primary.
4. Update the GH Actions secret with the new subkey export.
5. Re-sign the current Release file.
6. Update the fingerprint published in this document if the
   *primary* fingerprint changed (subkey rotation alone doesn't —
   users still trust the primary, and apt 1.8+ follows the chain
   automatically).

**If the primary key is suspected compromised:**

1. Apply the pre-generated revocation cert (it's hardcopy; OCR or
   retype). Export the revoked public key.
2. Generate a new primary key + subkey from scratch on a fresh
   air-gapped machine.
3. Publish the new keyring as `kyc-keyring-2.gpg`. Update the
   `apt-transport-kyc` package to install both during a transition
   window (typically 1 year).
4. Update the fingerprint here.
5. Every existing apt source will fail until users re-fetch the
   keyring (`curl -fsSL https://apt.knowyourco.de/install/kyc-keyring.gpg
   -o /etc/apt/keyrings/kyc-keyring.gpg`) and trust the new
   fingerprint. This is the nuclear scenario; it is why the primary
   is offline + on hardware.

## Why GPG instead of cosign / sigstore / cloud KMS?

apt itself only understands GPG-format `Release.gpg` /
`InRelease`. Sigstore is for OCI/container images; apt clients
won't parse it. Cloud KMS (AWS, GCP) can sign arbitrary bytes but
not produce GPG-format wrapping without a custom adapter. For a
small static apt repo, the YubiKey + offline-primary + CI-subkey
pattern (which is what Debian Project maintainers, Ubuntu
maintainers, and most third-party debs use) is both simpler and
more vendor-neutral than rolling a KMS adapter.
