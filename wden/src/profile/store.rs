use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::Context;
use directories_next::ProjectDirs;

use super::data::ProfileData;

#[derive(Clone)]
pub struct ProfileStore {
    config_dir: PathBuf,
    profile_config_file: PathBuf,
}

impl ProfileStore {
    pub fn new(profile_name: &str) -> ProfileStore {
        let profile_config_file = profile_file_path(profile_name);

        ProfileStore {
            config_dir: get_config_dir(),
            profile_config_file,
        }
    }

    pub fn get_all_profiles() -> std::io::Result<Vec<(String, ProfileData)>> {
        let config_dir = get_config_dir();
        let files = match std::fs::read_dir(config_dir) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e),
        };

        let json_ext = OsString::from_str("json").unwrap();

        let profiles = files
            .filter_map(Result::ok)
            .filter(|f| f.file_type().map(|t| t.is_file()).unwrap_or(false))
            .filter(|f| f.path().extension() == Some(json_ext.as_os_str()))
            .filter_map(|f| {
                let d = Self::load_file(&f.path()).ok()?;
                let name = f.path().file_stem()?.to_string_lossy().into();
                Some((name, d))
            })
            .collect();

        Ok(profiles)
    }

    pub fn load(&self) -> Result<ProfileData, anyhow::Error> {
        Self::load_file(&self.profile_config_file)
    }

    fn load_file(path: &Path) -> Result<ProfileData, anyhow::Error> {
        let contents = std::fs::read(path)?;
        let parsed: ProfileData = serde_json::from_slice(&contents)?;

        let migrated = parsed.run_migrations()?;

        Ok(migrated)
    }

    #[cfg(feature = "puppet-integration-tests")]
    pub fn delete(profile_name: &str) -> Result<(), anyhow::Error> {
        let path = profile_file_path(profile_name);
        match std::fs::remove_file(path) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).context("Failed to delete profile file"),
        }
    }

    pub fn store(&self, data: &ProfileData) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.config_dir)?;
        let serialized = serde_json::to_vec_pretty(data)?;

        std::fs::write(&self.profile_config_file, serialized)
    }

    pub fn edit<F>(&self, editor: F) -> Result<(), anyhow::Error>
    where
        F: FnOnce(&mut ProfileData),
    {
        // Load existing file for mutation
        let mut data = self.load()?;
        // Make changes
        editor(&mut data);
        // Store the edited data
        self.store(&data).context("Rewriting profile file failed")
    }
}

fn profile_file_path(profile_name: &str) -> PathBuf {
    get_config_dir().join(format!("{profile_name}.json"))
}

fn get_config_dir() -> PathBuf {
    let dirs = ProjectDirs::from("com.lkoskela", "", "wden").unwrap();
    dirs.config_dir().to_path_buf()
}
