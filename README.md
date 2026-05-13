# apt-transport-kyc

APT transport method for installing [Know Your Code](https://knowyourco.de) via `apt`.

This crate ships two things:

1. The **binary** `/usr/lib/apt/methods/kyc` — a custom APT transport
   that adds the `kyc+https://` URL scheme to apt. Packages under
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

The binary is shipped as a Debian package built by this repo's CI.
See [SECURITY.md](./SECURITY.md) for the GPG signing trust model and
[knowyourco.de/install/linux](https://knowyourco.de/install/linux)
for end-user install docs.

Supported Debian/Ubuntu versions: 11 (bullseye) / 20.04 (focal) and
newer, because the `signed-by=` apt sources directive and subkey-
signed Release files require apt 1.8+.

## License

Dual MIT / Apache-2.0.
