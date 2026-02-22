pub trait PlatformKeystore {
    fn store_key(&mut self, data: &[u8]) -> anyhow::Result<()>;
    fn retrieve_key_to<'a>(&mut self, buf: &'a mut [u8]) -> anyhow::Result<&'a [u8]>;
}


pub fn get_platform_keystore() -> anyhow::Result<Box<dyn PlatformKeystore>> {
    linux_keystore::get_linux_keystore()
}

#[cfg(target_os = "linux")]
mod linux_keystore;
#[cfg(target_os = "linux")]
pub type PlatformKeystoreImpl = linux_keystore::LinuxKeystore;
