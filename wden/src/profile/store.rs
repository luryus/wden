use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    str::FromStr,
};

use directories_next::ProjectDirs;

use super::data::ProfileData;

#[derive(Clone)]
pub struct ProfileStore {
    config_dir: PathBuf,
    profile_config_file: PathBuf,
}

impl ProfileStore {
    pub fn new(profile_name: &str) -> ProfileStore {
        let config_dir = get_config_dir();
        let profile_config_file = config_dir.join(format!("{profile_name}.json"));

        ProfileStore {
            config_dir,
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
                Some((f.file_name().into_string().unwrap(), d))
            })
            .collect();

        Ok(profiles)
    }

    pub fn load(&self) -> std::io::Result<ProfileData> {
        Self::load_file(&self.profile_config_file)
    }

    fn load_file(path: &Path) -> std::io::Result<ProfileData> {
        let contents = std::fs::read(path)?;
        let parsed = serde_json::from_slice(&contents)?;

        Ok(parsed)
    }

    pub fn store(&self, data: &ProfileData) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.config_dir)?;
        let serialized = serde_json::to_vec_pretty(data)?;

        std::fs::write(&self.profile_config_file, serialized)
    }

    pub fn edit<F>(&self, editor: F) -> std::io::Result<()>
    where
        F: FnOnce(&mut ProfileData),
    {
        // Load existing file for mutation
        let mut data = self.load()?;
        // Make changes
        editor(&mut data);
        // Store the edited data
        self.store(&data)
    }
}

fn get_config_dir() -> PathBuf {
    let dirs = ProjectDirs::from("com.lkoskela", "", "wden").unwrap();
    dirs.config_dir().to_path_buf()
}
