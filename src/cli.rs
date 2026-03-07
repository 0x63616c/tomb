pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("tomb v{}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
