fn main() {
    eprintln!(
        "aegis {} — research runtime for secure agent tool execution (scaffold)",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("Pipeline: policy → capability → sandbox → audit");
    std::process::exit(0);
}
