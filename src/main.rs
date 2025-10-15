use clap::Parser;
use env_logger;
use samplicator::app::run;
use samplicator::cli::Cli;

fn main() {
    env_logger::init();

    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("{}", e);

        std::process::exit(1);
    }
}
