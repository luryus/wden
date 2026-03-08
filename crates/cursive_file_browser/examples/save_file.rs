use cursive::{Cursive, CursiveExt, views::Dialog};
use cursive_file_browser::save_file_dialog;

fn main() {
    let mut siv = Cursive::default();

    siv.add_layer(
        Dialog::text("Press the button to open the save file dialog.")
            .title("File Browser Example")
            .button("Save file...", |siv| {
                let dialog = save_file_dialog("Save attachment", "example.txt", |siv, path| {
                    siv.add_layer(
                        Dialog::text(format!("Selected: {}", path.display()))
                            .title("Result")
                            .button("Save another...", |siv| {
                                siv.pop_layer();
                                let dialog = save_file_dialog(
                                    "Save attachment",
                                    "another_file.txt",
                                    |siv, path| {
                                        siv.add_layer(
                                            Dialog::text(format!(
                                                "Selected: {}",
                                                path.display()
                                            ))
                                            .title("Result")
                                            .dismiss_button("OK"),
                                        );
                                    },
                                );
                                siv.add_layer(dialog);
                            })
                            .dismiss_button("Close"),
                    );
                });
                siv.add_layer(dialog);
            })
            .button("Quit", |siv| siv.quit()),
    );

    siv.run();
}
