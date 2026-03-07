fn main() {
    if let Err(e) = tomb::cli::run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
