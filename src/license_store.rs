//! Read + write the local license file, with the precedence policy
//! the apt method needs.
//!
//! The kyc binary itself (`crates/kyc-license/src/lib.rs::default_license_path`)
//! reads `$HOME/.kyc/license`. apt runs the method as root, where
//! `$HOME` is `/root` — not where users actually keep credentials.
//! So:
//!
//! **Read precedence:** first `$HOME/.kyc/license` (the SUDO_USER's
//! home, or root's), then fall back to `/etc/kyc/license` (system-
//! wide path, idiomatic for FHS).
//!
//! **Write policy** (after bootstrapping via the device flow):
//! - If `$SUDO_USER` is set (the normal `sudo apt install` case),
//!   write to that user's `~/.kyc/license` with mode 0600, chown'd to
//!   their uid:gid. The user's daily `kyc` shell invocations then
//!   pick it up via `default_license_path()`.
//! - If `$SUDO_USER` is unset (raw root login, containers,
//!   unattended-upgrades), write to `/etc/kyc/license` mode 0644.
//!   The license is non-secret (it's a public token + Ed25519
//!   signature) so a slightly looser umask is fine; the `kyc-storage`
//!   crate's `/etc/kyc/` fallback picks it up on read.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::ptr;

/// System-wide fallback location, queried by `kyc` on Linux when
/// `$HOME/.kyc/license` is absent.
pub const SYSTEM_LICENSE_PATH: &str = "/etc/kyc/license";

/// Read the license file, trying `$HOME/.kyc/license` first then the
/// system-wide path. Returns `None` if neither exists; surfaces I/O
/// errors otherwise (e.g. permission denied on a file that does
/// exist).
pub fn read() -> io::Result<Option<Vec<u8>>> {
    if let Some(home_path) = home_license_path() {
        match fs::read(&home_path) {
            Ok(bytes) => return Ok(Some(bytes)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {} // fall through
            Err(err) => return Err(err),
        }
    }
    match fs::read(SYSTEM_LICENSE_PATH) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Write the license to disk, choosing the path + permissions per the
/// policy described in the module header. Returns the path written.
pub fn write(license: &[u8]) -> io::Result<PathBuf> {
    if let Some(sudo_user) = std::env::var_os("SUDO_USER") {
        if let Some((home, uid, gid)) = lookup_pwnam(&sudo_user)? {
            let dir = home.join(".kyc");
            fs::create_dir_all(&dir)?;
            // Apply 0700 on the directory only if it didn't exist
            // already — don't squash an existing user-chosen mode.
            chown_path(&dir, uid, gid)?;
            let path = dir.join("license");
            atomic_write_with_mode(&path, license, 0o600)?;
            chown_path(&path, uid, gid)?;
            return Ok(path);
        }
        // SUDO_USER set but unknown — fall through to /etc/kyc/.
    }
    let path = PathBuf::from(SYSTEM_LICENSE_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    atomic_write_with_mode(&path, license, 0o644)?;
    Ok(path)
}

fn home_license_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".kyc").join("license"))
}

fn atomic_write_with_mode(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let tmp = path.with_extension("license.tmp");
    fs::write(&tmp, bytes)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, path)
}

/// Look up the passwd entry for `name`. Returns `(home_dir, uid, gid)`
/// or `None` if the user doesn't exist on this system. Surfaces
/// libc-level errors otherwise.
fn lookup_pwnam(name: &std::ffi::OsStr) -> io::Result<Option<(PathBuf, u32, u32)>> {
    let cname = CString::new(name.as_bytes())
        .map_err(|_| io::Error::other("SUDO_USER contains NUL byte"))?;
    // SAFETY: getpwnam returns a pointer to a static buffer. We read
    // the fields once and copy them out before the next libc call;
    // pw_dir's bytes are owned by libc and remain valid until the
    // next getpwnam/getpwuid in this thread.
    unsafe {
        // Reset errno so we can distinguish "not found" from "error".
        let pwd = libc::getpwnam(cname.as_ptr());
        if pwd.is_null() {
            let errno = io::Error::last_os_error();
            // getpwnam returns NULL for both "not found" (errno == 0)
            // and real errors (errno != 0).
            if errno.raw_os_error() == Some(0) {
                return Ok(None);
            }
            return Err(errno);
        }
        if (*pwd).pw_dir == ptr::null_mut() {
            return Ok(None);
        }
        let dir = std::ffi::CStr::from_ptr((*pwd).pw_dir);
        let home = PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()));
        Ok(Some((home, (*pwd).pw_uid, (*pwd).pw_gid)))
    }
}

fn chown_path(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("path contains NUL byte"))?;
    // SAFETY: chown is a thread-safe libc call taking a NUL-terminated
    // path; the CString lives through the call.
    let rc = unsafe { libc::chown(cpath.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
