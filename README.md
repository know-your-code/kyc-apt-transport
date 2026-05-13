# apt-transport-kyc

APT transport method for installing [Know Your Code](https://knowyourco.de) via `apt`.

This crate ships two things:

1. The **binary** `/usr/lib/apt/methods/kyc` — a custom APT transport
   that adds the `kyc://` URL scheme to apt. Packages under
   `/pool/` are fetched with a license-file bearer credential
   (`Authorization: Kyc-License <base64-of-~/.kyc/license>`),
   verified offline by the upstream worker against the same Ed25519
   key baked into the released kyc binary.

2. The **library** `apt_transport_kyc::device_flow` — the RFC 8628
   OAuth Device Authorization Grant client the binary uses on first
   install. **Also re-used by the main kyc CLI** (`kyc license sso`)
   via a git dependency, so there's exactly one implementation of
   the device flow across the project.

## Library use

Add to `Cargo.toml`:

```toml
apt-transport-kyc = {
    git = "https://github.com/know-your-code/kyc-apt-transport",
    rev = "<commit-sha>",
    features = ["cli-ui"],          # enables the browser-launch arm
    default-features = false,
}
```

Then:

```rust
use apt_transport_kyc::device_flow::{self, DeviceFlowConfig, UserIo};

let config = DeviceFlowConfig::defaults(
    format!("my-cli/{}", env!("CARGO_PKG_VERSION")),
    UserIo::Cli { enable_browser: true },
);
let license_pem = device_flow::run(config)?;
```

The crate has no other public API today; the `protocol` and
`license_store` modules are exposed for the binary's internal use
and are not considered stable.

## Binary install

The binary ships as a Debian package built by this repo's CI and
published to `https://apt.knowyourco.de/install/`. The `.deb` ships
exactly one thing: the apt-method binary at
`/usr/lib/apt/methods/kyc`. No maintainer scripts, no bundled
keyring, no automatic sources.list registration — the install flow
on Debian/Ubuntu follows Docker's pattern (explicit, auditable
commands the user runs themselves):

```sh
# 1. Prerequisites
sudo apt update
sudo apt install -y ca-certificates curl

# 2. Trust the kyc signing key
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://apt.knowyourco.de/install/kyc-keyring.gpg \
  -o /etc/apt/keyrings/kyc-keyring.gpg
sudo chmod a+r /etc/apt/keyrings/kyc-keyring.gpg

# 3. Register the bootstrap apt source (plain HTTPS, ships apt-transport-kyc)
sudo tee /etc/apt/sources.list.d/kyc.sources > /dev/null <<EOF
Types: deb
URIs: https://apt.knowyourco.de
Suites: bootstrap
Components: main
Signed-By: /etc/apt/keyrings/kyc-keyring.gpg
EOF

# 4. Install the apt transport (gives apt the kyc:// scheme)
sudo apt update
sudo apt install -y apt-transport-kyc

# 5. Append the licensed source (kyc itself)
sudo tee -a /etc/apt/sources.list.d/kyc.sources > /dev/null <<EOF

Types: deb
URIs: kyc://apt.knowyourco.de
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/kyc-keyring.gpg
EOF

# 6. Install kyc
sudo apt update
sudo apt install -y kyc
```

The canonical version of this flow lives at
[knowyourco.de/download](https://knowyourco.de/download). See
[SECURITY.md](./SECURITY.md) for the GPG signing trust model.

Supported Debian/Ubuntu versions: 11 (bullseye) / 20.04 (focal) and
newer, because the `Signed-By:` field in deb822 sources and subkey-
signed Release files require apt 1.8+.

## License

Dual MIT / Apache-2.0.
