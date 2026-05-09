//! Per-OS keystore-encryption shims. Returns ciphertext bytes that the
//! mod.rs layer writes to disk.
//!
//! - **Windows** (`cfg(windows)`): DPAPI `CryptProtectData` / `CryptUnprotectData`
//!   keyed to the local user account. Defense in depth: a cold copy of
//!   the file taken to another machine cannot be decrypted.
//! - **Other** (M2 follow-up): unimplemented at this point. Compiles to
//!   a stub that returns an explicit error so a non-Windows build of M2
//!   fails honestly rather than persisting plaintext.

#[cfg(windows)]
mod windows_dpapi {
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CryptProtectData, CryptUnprotectData,
    };

    /// Encrypt with DPAPI to current user. Returns ciphertext.
    pub fn encrypt(plain: &[u8]) -> Result<Vec<u8>, String> {
        // SAFETY: We pass `plain` as a non-null pointer with the correct
        // matching length. CryptProtectData allocates the output via
        // LocalAlloc; we copy into a Vec<u8> and free via LocalFree.
        // No outliving references; cb_data is stack-only, output blob is
        // freed before the function returns.
        unsafe {
            let in_blob = CRYPT_INTEGER_BLOB {
                cbData: u32::try_from(plain.len())
                    .map_err(|_| "plaintext too large for DPAPI".to_string())?,
                pbData: plain.as_ptr() as *mut u8,
            };
            let mut out_blob = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: null_mut(),
            };

            let ok = CryptProtectData(
                &in_blob,
                null_mut(), // description
                null_mut(), // optional entropy
                null_mut(), // reserved
                null_mut(), // prompt struct
                0,          // flags
                &mut out_blob,
            );
            if ok == 0 {
                return Err(format!(
                    "CryptProtectData failed: error {}",
                    windows_sys::Win32::Foundation::GetLastError()
                ));
            }

            let len = out_blob.cbData as usize;
            let mut buf = Vec::with_capacity(len);
            std::ptr::copy_nonoverlapping(out_blob.pbData, buf.as_mut_ptr(), len);
            buf.set_len(len);
            // SAFETY: out_blob.pbData was allocated by DPAPI via LocalAlloc.
            LocalFree(out_blob.pbData as _);
            Ok(buf)
        }
    }

    /// Decrypt a blob produced by [`encrypt`].
    pub fn decrypt(cipher: &[u8]) -> Result<Vec<u8>, String> {
        // SAFETY: same shape as encrypt — non-null pointer + matching
        // length; output blob freed via LocalFree before return.
        unsafe {
            let in_blob = CRYPT_INTEGER_BLOB {
                cbData: u32::try_from(cipher.len())
                    .map_err(|_| "ciphertext too large for DPAPI".to_string())?,
                pbData: cipher.as_ptr() as *mut u8,
            };
            let mut out_blob = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: null_mut(),
            };

            let ok = CryptUnprotectData(
                &in_blob,
                null_mut(), // description out — we don't care
                null_mut(),
                null_mut(),
                null_mut(),
                0,
                &mut out_blob,
            );
            if ok == 0 {
                return Err(format!(
                    "CryptUnprotectData failed: error {}",
                    windows_sys::Win32::Foundation::GetLastError()
                ));
            }

            let len = out_blob.cbData as usize;
            let mut buf = Vec::with_capacity(len);
            std::ptr::copy_nonoverlapping(out_blob.pbData, buf.as_mut_ptr(), len);
            buf.set_len(len);
            LocalFree(out_blob.pbData as _);
            Ok(buf)
        }
    }
}

#[cfg(windows)]
pub use windows_dpapi::{decrypt, encrypt};

#[cfg(not(windows))]
mod stub {
    /// macOS Keychain + Linux libsecret/machine-id-AEAD land in their
    /// own M2 follow-up sessions. Building/running the daemon on
    /// non-Windows in the M2 baseline is intentionally an error rather
    /// than a silent plaintext fallback (Principle 1).
    pub fn encrypt(_plain: &[u8]) -> Result<Vec<u8>, String> {
        Err("keystore encryption not implemented on this platform yet (M2 Win-only)".into())
    }

    /// See [`encrypt`].
    pub fn decrypt(_cipher: &[u8]) -> Result<Vec<u8>, String> {
        Err("keystore encryption not implemented on this platform yet (M2 Win-only)".into())
    }
}

#[cfg(not(windows))]
pub use stub::{decrypt, encrypt};
