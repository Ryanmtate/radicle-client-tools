use anyhow::{anyhow, bail};
use coins_bip32::path::DerivationPath;
use colored::*;
use console::Term;
use dialoguer::{theme::ColorfulTheme, Select};
use ethers::{
    signers::{HDPath, Ledger, Signer},
    types::H160,
};
use git2::{Oid, Repository};
use std::{fmt::Debug, path::PathBuf};

const NOTES_REF: &str = "refs/notes/radicle/rewards";

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Puzzle {
    org: H160,
    contributor: H160,
    commit: String,
    project: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Proof {
    org: H160,
    contributor: H160,
    commit: String,
    project: String,
    org_sig: String,
}

/// Retrieves all notes from repo.
/// Lets user chose which of the commits to claim.
/// Obtains the proof stored in the commit
/// Creates the transaction object, signs it by the contributor
/// And sends it to the NFT factory
pub fn claim(options: Options) -> anyhow::Result<()> {
    let repo_path = options
        .repo
        .ok_or_else(|| anyhow!(Error::ArgMissing("No repo path specified".into())))?;

    let repo = match Repository::open(repo_path) {
        Ok(repo) => repo,
        Err(e) => bail!("failed to open repo {}", e),
    };

    let mut commits: Vec<Oid> = Vec::new();

    for note in repo.notes(Some(NOTES_REF))? {
        commits.push(note.unwrap().1);
    }

    let selection = Select::with_theme(&ColorfulTheme::default())
        .items(&commits)
        .with_prompt("Claimable Commits")
        .interact_on_opt(&Term::stderr())?;

    let index = match selection {
        Some(index) => index,
        None => bail!("User did not select any commit"),
    };
    log::debug!("Selected commit: {:?}", commits[index]);

    let t = repo.find_note(Some(NOTES_REF), commits[index])?;
    log::debug!("Selected note: {:?}", t.id());

    let t = match t.message() {
      Some(msg) => msg,
      None => bail!("Not able to obtain commit message")
    };

    let msg: Proof = serde_json::from_str(t)?;

    log::debug!("Retrieved Puzzle: {:?}", msg);

    Ok(())
}

/// Creates a revwalk over the git repo
/// Starting from the head iterates over all commits backwards, filtering out the ones that already have contribution notes
/// Printing out a summary of all the commits which have no rewards defined
pub fn discover(options: Options) -> anyhow::Result<()> {
    let repo_path = options
        .repo
        .ok_or_else(|| anyhow!(Error::ArgMissing("No repo path specified".into())))?;

    let repo = match Repository::open(repo_path) {
        Ok(repo) => repo,
        Err(e) => panic!("failed to open repo {}", e),
    };
    let head = repo.head()?;
    let target = match head.target() {
      Some(oid) => oid,
      None => bail!("Not able to find HEAD")
    };

    let mut walk = repo.revwalk()?;
    walk.push(target)?;

    let oids: Vec<Oid> = walk
        .by_ref()
        .filter(|r| -> bool {
            let oid = r
                .as_ref()
                .map_err(|_| anyhow!(Error::CommitNotExisting))
                .expect("Not able to map error");
            repo.find_note(Some(NOTES_REF), *oid).is_err()
        })
        .collect::<Result<Vec<_>, _>>()?;

    println!("{}", "Commits without existing puzzles".bold());
    for oid in oids {
        let commit = format_commit(&repo, &oid)?;
        println!("{} {}", commit.0, commit.1);
    }
    Ok(())
}

/// Opens the repo checks if the passed commit exists on the repo
/// With the commit hash and other params,creates the message
/// The message is getting signed with a Ledger HW or a keystore file.
/// And stored as a git note on the specified commit
pub async fn create(options: Options) -> anyhow::Result<()> {
    // Creating message
    // -------------------
    let oid = options
        .commit
        .ok_or_else(|| anyhow!(Error::ArgMissing("No commit specified".into())))?;
    let contributor = options
        .contributor
        .ok_or_else(|| anyhow!(Error::ArgMissing("No contributor address specified".into())))?;
    let project = options
        .project
        .ok_or_else(|| anyhow!(Error::ArgMissing("No project id specified".into())))?;
    let repo_path = options
        .repo
        .ok_or_else(|| anyhow!(Error::ArgMissing("No repo path specified".into())))?;

    let repo = match Repository::open(repo_path) {
        Ok(repo) => repo,
        Err(e) => panic!("failed to open repo {}", e),
    };
    let commit = repo
        .find_commit(oid)
        .map_err(|_| anyhow!(Error::CommitNotExisting))?;

    // Sign message
    // -----------------------
    if let Some(keypath) = &options.keystore {
        let prompt = format!("{} Password: ", "??".cyan());
        let password = rpassword::prompt_password_stdout(&prompt)?;
        let signer = ethers::signers::LocalWallet::decrypt_keystore(keypath, password)
            .map_err(|_| anyhow!("keystore decryption failed"))?;

        let msg = create_puzzle(signer, contributor, commit.id().to_string(), project).await?;

        let repo_sig = repo.signature()?;
        let note = repo.note(
            &repo_sig,
            &repo_sig,
            Some(NOTES_REF),
            commit.id(),
            &msg,
            true,
        )?;
        log::debug!(
            "note id {}\ncreated on commit {}\nwith content {}",
            note,
            commit.id(),
            &msg
        );

        Ok(())
    } else if let Some(path) = &options.ledger_hdpath {
        let hdpath = path.derivation_string();
        let signer = Ledger::new(HDPath::Other(hdpath), 1).await?;

        let msg = create_puzzle(signer, contributor, commit.id().to_string(), project).await?;

        let repo_sig = repo.signature()?;
        let note = repo.note(
            &repo_sig,
            &repo_sig,
            Some(NOTES_REF),
            commit.id(),
            &msg,
            true,
        )?;
        log::debug!(
            "note id {}\ncreated on commit {}\nwith content {}",
            note,
            commit.id(),
            &msg
        );

        Ok(())
    } else {
        Err(anyhow!(Error::ArgMissing(
            "no wallet specified: either '--ledger-hdpath' or '--keystore' must be specified"
                .into()
        )))
    }
}

fn format_commit(repo: &Repository, oid: &Oid) -> anyhow::Result<(String, String)> {
    let commit = repo.find_commit(*oid)?;
    let summary = commit
        .summary()
        .ok_or_else(|| anyhow!(Error::NotValidEncoding("commit summary".into())))?;
    Ok((oid.to_string()[..7].into(), summary.into()))
}

async fn create_puzzle<S: Signer>(
    signer: S,
    contributor: H160,
    commit: String,
    project: String,
) -> anyhow::Result<String> {
    // Instantiate of puzzle
    let puzzle = Puzzle {
        org: signer.address(),
        contributor,
        commit: commit.to_owned(),
        project: project.to_owned(),
    };

    // Signing of puzzle and creation of signature
    let puzzle_json = serde_json::to_string(&puzzle)?;
    let sig = signer.sign_message(&puzzle_json).await;
    let sig = sig.map_err(|_| anyhow!(Error::SignFailure))?;
    sig.verify(puzzle_json.to_owned(), signer.address())?;

    // Creation of proof json
    serde_json::to_string(&Proof {
        org: signer.address(),
        contributor,
        commit,
        project,
        org_sig: sig.to_string(),
    })
    .map_err(|_| anyhow!(Error::SerializeFailure))
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// No wallet specified.
    #[error("Missing Argument: {0}")]
    ArgMissing(String),
    /// Not able to retrieve block .
    #[error("not able to retrieve block")]
    NoBlock,
    /// Not able to retrieve block hash .
    #[error("not able to retrieve block hash")]
    NoBlockHash,
    /// Not able to retrieve commit.
    #[error("not able to retrieve commit")]
    CommitNotExisting,
    /// Not able to sign message
    #[error("not able to sign message")]
    SignFailure,
    /// Not able to sign message
    #[error("not able to sign message")]
    SerializeFailure,
    /// Not valid commit summary
    #[error("{0} not valid")]
    NotValidEncoding(String),
    /// ETH signature failed
    #[error("eth signature failed")]
    ETHSigFailed,
    /// GPG signature failed
    #[error("{0}")]
    GPGSigFailed(String),
}

/// The options allowed to be provided to the CLI
#[derive(Debug, Clone)]
pub struct Options {
    /// Address of org.
    pub org: Option<H160>,
    /// Address of contributor
    pub contributor: Option<H160>,
    /// Repo path
    pub repo: Option<PathBuf>,
    /// Project id.
    pub project: Option<String>,
    /// Account derivation path when using a Ledger hardware wallet.
    pub ledger_hdpath: Option<DerivationPath>,
    /// Keystore file containing encrypted private key (default: none).
    pub keystore: Option<PathBuf>,
    /// SHA1 Hash of commit to reward
    pub commit: Option<Oid>,
}
