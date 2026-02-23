use std::cell::RefCell;

use zeroize::Zeroizing;

use crate::bitwarden::cipher::EncMacKeys;

pub trait PlatformKeystore {
    fn store_key(&mut self, data: &[u8]) -> anyhow::Result<()>;
    fn retrieve_key_to<'a>(&mut self, buf: &'a mut [u8]) -> anyhow::Result<&'a [u8]>;

    fn store_enc_mac_keys(&mut self, keys: &EncMacKeys) -> anyhow::Result<()> {
        let mut buf = Zeroizing::new([0u8; EncMacKeys::total_len()]);
        keys.store_to_slice(buf.as_mut_slice())?;
        self.store_key(buf.as_slice())?;
        Ok(())
    }
    fn retrieve_enc_mac_keys(&mut self) -> anyhow::Result<EncMacKeys> {
        let mut buf = Zeroizing::new([0u8; EncMacKeys::total_len()]);
        let key_data = self.retrieve_key_to(buf.as_mut_slice())?;
        let keys = EncMacKeys::from_slice(key_data)?;
        Ok(keys)
    }
}

pub fn get_platform_keystore() -> anyhow::Result<Box<RefCell<dyn PlatformKeystore>>> {
    linux_keystore::get_linux_keystore()
}

#[cfg(target_os = "linux")]
mod linux_keystore;
#[cfg(target_os = "linux")]
pub type PlatformKeystoreImpl = linux_keystore::LinuxKeystore;
