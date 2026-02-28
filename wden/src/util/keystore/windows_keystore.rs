use std::cell::RefCell;

use anyhow::Context;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
};
use zeroize::Zeroizing;

use super::PlatformKeystore;

pub struct WindowsKeystore {
    encrypted_data: Option<Zeroizing<Vec<u8>>>,
}

pub fn get_windows_keystore() -> anyhow::Result<Box<RefCell<dyn PlatformKeystore>>> {
    Ok(Box::new(RefCell::new(WindowsKeystore {
        encrypted_data: None,
    })))
}

/// Wrapper around a CRYPT_INTEGER_BLOB whose pbData was allocated by a
/// Windows API function (e.g. CryptProtectData) via LocalAlloc.
/// On drop: zeroizes the buffer contents, then frees with LocalFree.
struct OwnedCryptBlob(CRYPT_INTEGER_BLOB);

impl OwnedCryptBlob {
    /// Create an empty blob to be filled by a DPAPI call.
    fn new_empty() -> Self {
        Self(CRYPT_INTEGER_BLOB::default())
    }

    /// Get a mutable pointer to the inner blob for passing to DPAPI as an output parameter.
    fn as_out_ptr(&mut self) -> *mut CRYPT_INTEGER_BLOB {
        &mut self.0
    }

    fn as_slice(&self) -> &[u8] {
        if self.0.pbData.is_null() || self.0.cbData == 0 {
            return &[];
        }
        // SAFETY: After a successful DPAPI call, pbData points to cbData
        // bytes allocated via LocalAlloc.
        unsafe { std::slice::from_raw_parts(self.0.pbData, self.0.cbData as usize) }
    }
}

impl Drop for OwnedCryptBlob {
    fn drop(&mut self) {
        if self.0.pbData.is_null() {
            return;
        }
        unsafe {
            // SAFETY: pbData was allocated by a DPAPI function via LocalAlloc.
            // Zeroize before freeing to avoid leaving sensitive data in freed heap.
            std::ptr::write_bytes(self.0.pbData, 0, self.0.cbData as usize);
            let _ = LocalFree(Some(HLOCAL(self.0.pbData as *mut _)));
        }
        self.0.pbData = std::ptr::null_mut();
        self.0.cbData = 0;
    }
}

impl PlatformKeystore for WindowsKeystore {
    fn store_key(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.encrypted_data = None; // drop + zeroize any existing via Zeroizing

        let mut input_copy = Zeroizing::new(data.to_vec());
        let input_blob = CRYPT_INTEGER_BLOB {
            cbData: input_copy.len() as u32,
            pbData: input_copy.as_mut_ptr(),
        };
        let mut output = OwnedCryptBlob::new_empty();

        // SAFETY: input_blob.pbData points to valid owned buffer for duration of call.
        // output is populated by the API on success.
        unsafe {
            CryptProtectData(&input_blob, None, None, None, None, 0, output.as_out_ptr())
                .context("CryptProtectData failed")?;
        }

        self.encrypted_data = Some(Zeroizing::new(output.as_slice().to_vec()));
        Ok(())
    }

    fn retrieve_key_to<'a>(&mut self, buf: &'a mut [u8]) -> anyhow::Result<&'a [u8]> {
        let mut encrypted = self
            .encrypted_data
            .take()
            .context("No encrypted data stored")?;

        let input_blob = CRYPT_INTEGER_BLOB {
            cbData: encrypted.len() as u32,
            pbData: encrypted.as_mut_ptr(),
        };
        let mut output = OwnedCryptBlob::new_empty();

        // SAFETY: input_blob.pbData points to owned encrypted Vec buffer.
        // output is populated by the API on success.
        unsafe {
            CryptUnprotectData(&input_blob, None, None, None, None, 0, output.as_out_ptr())
                .context("CryptUnprotectData failed")?;
        }

        let decrypted = output.as_slice();
        anyhow::ensure!(
            decrypted.len() <= buf.len(),
            "Decrypted data ({}) exceeds buffer size ({})",
            decrypted.len(),
            buf.len()
        );
        buf[..decrypted.len()].copy_from_slice(decrypted);
        let len = decrypted.len();

        Ok(&buf[..len])
    }
}
