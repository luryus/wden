use super::PlatformKeystore;

use anyhow::Context;
use linux_keyutils::{Key, KeyRing, KeyRingIdentifier};

pub struct LinuxKeystore {
    keyring: KeyRing,
    lock_key: Option<Key>,
}

pub fn get_linux_keystore() -> anyhow::Result<Box<dyn PlatformKeystore>> {
    let keyring =
        KeyRing::from_special_id(KeyRingIdentifier::Process, true).context("KeyRing init fail")?;

    Ok(Box::new(LinuxKeystore {
        keyring,
        lock_key: None,
    }))
}

impl PlatformKeystore for LinuxKeystore {
    fn store_key(&mut self, key_data: &[u8]) -> anyhow::Result<()> {
        if let Some(existing_key) = self.lock_key.take() {
            existing_key
                .invalidate()
                .context("Invalidating existing key failed")?;
        }

        let key = self
            .keyring
            .add_key("lock_key", key_data)
            .context("Adding key failed")?;
        self.lock_key = Some(key);

        Ok(())
    }

    fn retrieve_key_to<'a>(&mut self, mut buf: &'a mut [u8]) -> anyhow::Result<&'a [u8]> {
        let key = self.lock_key.take().context("Lock key not present")?;
        let count = key.read(&mut buf).context("Data read failed")?;
        Ok(&buf[..count])
    }
}

