use indicatif::{ProgressBar, ProgressStyle};

pub fn new_transfer_progress(message: String, total_bytes: u64) -> ProgressBar {
    let pb = ProgressBar::new(total_bytes);
    let style = ProgressStyle::with_template(
        "{msg} {percent:>3}% |{bar:20.cyan/blue}| ({bytes}/{total_bytes}, {bytes_per_sec})",
    )
    .unwrap_or_else(|_| ProgressStyle::default_bar())
    .progress_chars("=>-");
    pb.set_style(style);
    pb.set_message(message);
    pb
}
