use std::path::{Path, PathBuf};
use std::sync::Arc;

use cursive_core::{
    Cursive, View,
    traits::{Nameable, Resizable},
    view::{Margins, Scrollable, ViewWrapper},
    views::{Dialog, EditView, LinearLayout, PaddedView, SelectView, TextView},
    wrap_impl,
};

const PATH_DISPLAY_NAME: &str = "file_browser_path_display";
const DIR_LIST_NAME: &str = "file_browser_dir_list";
const FILENAME_EDIT_NAME: &str = "file_browser_filename";

type SaveCallback = dyn Fn(&mut Cursive, PathBuf) + Send + Sync + 'static;

/// A save-file dialog that lets the user browse directories and pick a filename.
/// Returns the chosen PathBuf via a callback.
pub fn save_file_dialog(
    title: &str,
    default_filename: &str,
    on_save: impl Fn(&mut Cursive, PathBuf) + Send + Sync + 'static,
) -> impl View {
    let start_dir = default_start_dir();

    let path_display =
        TextView::new(start_dir.display().to_string()).with_name(PATH_DISPLAY_NAME);

    let mut dir_list = SelectView::<PathBuf>::new();
    populate_dir_list(&mut dir_list, &start_dir);
    dir_list.set_on_submit(on_dir_selected);
    let dir_list = dir_list
        .with_name(DIR_LIST_NAME)
        .scrollable()
        .min_height(10)
        .max_height(20);

    let filename_edit = EditView::new()
        .content(default_filename)
        .with_name(FILENAME_EDIT_NAME)
        .min_width(30);

    let layout = LinearLayout::vertical()
        .child(PaddedView::new(Margins::tb(0, 1), path_display))
        .child(dir_list)
        .child(PaddedView::new(
            Margins::tb(1, 0),
            LinearLayout::horizontal()
                .child(TextView::new("File: "))
                .child(filename_edit),
        ))
        .min_width(50);

    let on_save: Arc<SaveCallback> = Arc::new(on_save);

    let dialog = Dialog::around(layout)
        .title(title)
        .button("Save", move |siv| {
            on_save_pressed(siv, Arc::clone(&on_save));
        })
        .dismiss_button("Cancel");

    SaveFileDialog { dialog }
}

struct SaveFileDialog {
    dialog: Dialog,
}

impl ViewWrapper for SaveFileDialog {
    wrap_impl!(self.dialog: Dialog);
}

fn default_start_dir() -> PathBuf {
    if let Some(user_dirs) = directories_next::UserDirs::new() {
        if let Some(downloads) = user_dirs.download_dir()
            && downloads.is_dir()
        {
            return downloads.to_path_buf();
        }
        let home = user_dirs.home_dir();
        if home.is_dir() {
            return home.to_path_buf();
        }
    }
    std::env::temp_dir()
}

fn populate_dir_list(list: &mut SelectView<PathBuf>, dir: &Path) {
    list.clear();

    if let Some(parent) = dir.parent() {
        list.add_item("../", parent.to_path_buf());
    } else {
        // At filesystem root — on Windows, show available drives
        #[cfg(windows)]
        for drive in get_windows_drives() {
            let label = drive.display().to_string();
            list.add_item(label, drive);
        }
    }

    // Read and sort directory entries
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();

    for entry in entries {
        if let Some(name) = entry.file_name().and_then(|n| n.to_str()) {
            list.add_item(format!("{name}{}", std::path::MAIN_SEPARATOR), entry);
        }
    }
}

#[cfg(windows)]
fn get_windows_drives() -> Vec<PathBuf> {
    // SAFETY: GetLogicalDrives is a simple FFI call with no unsafe preconditions
    let bitmask = unsafe { windows::Win32::Storage::FileSystem::GetLogicalDrives() };
    if bitmask == 0 {
        let err = std::io::Error::last_os_error();
        log::warn!("GetLogicalDrives failed: {err}");
        return vec![];
    }
    (0..26)
        .filter(|i| bitmask & (1 << i) != 0)
        .map(|i| PathBuf::from(format!("{}:\\", (b'A' + i) as char)))
        .collect()
}

fn on_dir_selected(siv: &mut Cursive, path: &Path) {
    let path = path.to_path_buf();
    siv.call_on_name(DIR_LIST_NAME, |view: &mut SelectView<PathBuf>| {
        populate_dir_list(view, &path);
    });
    siv.call_on_name(PATH_DISPLAY_NAME, |view: &mut TextView| {
        view.set_content(path.display().to_string());
    });
}

fn get_current_save_path(siv: &mut Cursive) -> Option<PathBuf> {
    let dir = siv.call_on_name(PATH_DISPLAY_NAME, |view: &mut TextView| {
        view.get_content().source().to_string()
    })?;
    let filename = siv.call_on_name(FILENAME_EDIT_NAME, |view: &mut EditView| {
        view.get_content().to_string()
    })?;

    if filename.is_empty() {
        return None;
    }

    Some(PathBuf::from(dir).join(filename))
}

fn on_save_pressed(siv: &mut Cursive, on_save: Arc<SaveCallback>) {
    let Some(path) = get_current_save_path(siv) else {
        siv.add_layer(Dialog::info("Please enter a filename."));
        return;
    };

    if path.exists() {
        let on_save = on_save.clone();
        let path_clone = path.clone();
        siv.add_layer(
            Dialog::text(format!(
                "File \"{}\" already exists. Overwrite?",
                path.display()
            ))
            .button("Overwrite", move |siv| {
                siv.pop_layer(); // pop confirmation
                siv.pop_layer(); // pop file browser
                on_save(siv, path_clone.clone());
            })
            .dismiss_button("Cancel"),
        );
    } else {
        siv.pop_layer(); // pop file browser
        on_save(siv, path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cursive_core::views::SelectView;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn populate_dir_list_shows_only_directories() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        fs::write(dir.path().join("file.txt"), "hello").unwrap();

        let mut list = SelectView::<PathBuf>::new();
        populate_dir_list(&mut list, dir.path());

        let items: Vec<String> = (0..list.len())
            .map(|i| list.get_item(i).unwrap().0.to_string())
            .collect();

        // Should have ../ and the subdirectory, but not the file
        assert!(items.iter().any(|i| i == "../"));
        assert!(items.iter().any(|i| i.starts_with("subdir")));
        assert!(!items.iter().any(|i| i.contains("file.txt")));
    }

    #[test]
    fn populate_dir_list_sorts_entries() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("charlie")).unwrap();
        fs::create_dir(dir.path().join("alpha")).unwrap();
        fs::create_dir(dir.path().join("bravo")).unwrap();

        let mut list = SelectView::<PathBuf>::new();
        populate_dir_list(&mut list, dir.path());

        // Skip the ../ entry, check the rest are sorted
        let dir_items: Vec<String> = (0..list.len())
            .map(|i| list.get_item(i).unwrap().0.to_string())
            .filter(|i| i != "../")
            .collect();

        assert_eq!(dir_items.len(), 3);
        assert!(dir_items[0].starts_with("alpha"));
        assert!(dir_items[1].starts_with("bravo"));
        assert!(dir_items[2].starts_with("charlie"));
    }

    #[test]
    fn populate_dir_list_includes_parent_entry() {
        let dir = tempdir().unwrap();
        let subdir = dir.path().join("sub");
        fs::create_dir(&subdir).unwrap();

        let mut list = SelectView::<PathBuf>::new();
        populate_dir_list(&mut list, &subdir);

        let first_label = list.get_item(0).unwrap().0.to_string();
        assert_eq!(first_label, "../");

        let first_value = list.get_item(0).unwrap().1;
        assert_eq!(*first_value, dir.path());
    }

    #[test]
    fn populate_dir_list_handles_empty_directory() {
        let dir = tempdir().unwrap();

        let mut list = SelectView::<PathBuf>::new();
        populate_dir_list(&mut list, dir.path());

        // Should only have the ../ entry
        assert_eq!(list.len(), 1);
        assert_eq!(list.get_item(0).unwrap().0, "../");
    }

    #[test]
    fn get_current_save_path_combines_dir_and_filename() {
        let dir = tempdir().unwrap();
        let dir_str = dir.path().display().to_string();

        let mut siv = Cursive::new();
        siv.add_layer(
            LinearLayout::vertical()
                .child(TextView::new(&dir_str).with_name(PATH_DISPLAY_NAME))
                .child(
                    EditView::new()
                        .content("test.txt")
                        .with_name(FILENAME_EDIT_NAME),
                ),
        );

        let path = get_current_save_path(&mut siv).unwrap();
        assert_eq!(path, dir.path().join("test.txt"));
    }

    #[test]
    fn get_current_save_path_returns_none_for_empty_filename() {
        let dir = tempdir().unwrap();
        let dir_str = dir.path().display().to_string();

        let mut siv = Cursive::new();
        siv.add_layer(
            LinearLayout::vertical()
                .child(TextView::new(&dir_str).with_name(PATH_DISPLAY_NAME))
                .child(EditView::new().with_name(FILENAME_EDIT_NAME)),
        );

        assert!(get_current_save_path(&mut siv).is_none());
    }

    #[test]
    fn save_file_dialog_constructs_without_panic() {
        let _view = save_file_dialog("Test", "file.txt", |_siv, _path| {});
    }
}
