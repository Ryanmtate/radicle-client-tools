use anyhow::anyhow;
use coins_bip32::path::DerivationPath;
use ethers::types::H160;
use git2::Oid;
use radicle_tools::logger;
use reward::{claim, create, discover, Options};
use std::{env, io::Write, path::PathBuf, process};

const USAGE: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/", "USAGE"));
const NAME: &str = env!("CARGO_CRATE_NAME");

enum Command {
    Create { options: Options, verbose: bool },
    Claim { options: Options, verbose: bool },
    Discover { options: Options, verbose: bool },
    Help,
}

fn parse_options() -> anyhow::Result<Command> {
    use lexopt::prelude::*;

    let mut parser = lexopt::Parser::from_env();
    let mut org: Option<H160> = None;
    let mut repo: Option<PathBuf> = None;
    let mut contributor: Option<H160> = None;
    let mut project: Option<String> = None;
    let mut ledger_hdpath: Option<DerivationPath> = None;
    let mut keystore: Option<PathBuf> = None;
    let mut commit: Option<Oid> = None;
    let mut verbose = false;

    while let Some(arg) = parser.next()? {
        match arg {
            Long("claim") => {
                return Ok(Command::Claim {
                    options: Options {
                        org,
                        contributor,
                        repo,
                        project,
                        ledger_hdpath,
                        keystore,
                        commit,
                    },
                    verbose,
                });
            }
            Long("discover") => {
                return Ok(Command::Discover {
                    options: Options {
                        org,
                        contributor,
                        repo,
                        project,
                        ledger_hdpath: None,
                        keystore: None,
                        commit: None,
                    },
                    verbose,
                })
            }
            Long("create") => {
                return Ok(Command::Create {
                    options: Options {
                        org,
                        contributor,
                        repo,
                        project,
                        ledger_hdpath,
                        keystore,
                        commit,
                    },
                    verbose,
                })
            }
            Long("repo") => {
                repo = Some(parser.value()?.parse()?);
            }
            Long("org") => {
                org = Some(parser.value()?.parse()?);
            }
            Long("contributor") => {
                contributor = Some(parser.value()?.parse()?);
            }
            Long("project") => {
                project = Some(parser.value()?.parse()?);
            }
            Long("commit") => {
                commit = Some(parser.value()?.parse()?);
            }
            Long("keystore") => {
                keystore = Some(parser.value()?.parse()?);
            }
            Long("ledger-hdpath") => {
                ledger_hdpath = Some(parser.value()?.parse()?);
            }
            Long("verbose") | Short('v') => {
                verbose = true;
            }
            Long("help") => {
                return Ok(Command::Help);
            }
            _ => {
                return Err(anyhow!(arg.unexpected()));
            }
        }
    }
    Ok(Command::Help)
}

#[tokio::main]
async fn main() {
    logger::init(NAME).unwrap();
    logger::set_level(log::Level::Error);

    match execute().await {
        Err(err) => {
            if let Some(cause) = err.source() {
                log::error!("Error: {} ({})", err, cause);
            } else {
                log::error!("Error: {}", err);
            }
            process::exit(1);
        }
        Ok(()) => {}
    }
}

async fn execute() -> anyhow::Result<()> {
    match parse_options()? {
        Command::Help => {
            std::io::stderr().write_all(USAGE)?;
            Ok(())
        }
        Command::Claim { options, verbose } => {
            set_debug_level(verbose);
            claim(options).await?;
            Ok(())
        }
        Command::Create { options, verbose } => {
            set_debug_level(verbose);
            create(options).await?;
            Ok(())
        }
        Command::Discover { options, verbose } => {
            set_debug_level(verbose);
            discover(options)?;
            Ok(())
        }
    }
}

fn set_debug_level(verbose: bool) {
    if verbose {
        logger::set_level(log::Level::Debug);
    } else {
        logger::set_level(log::Level::Info);
    }
}
