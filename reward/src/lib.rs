use anyhow::{anyhow, bail};
use coins_bip32::{path::DerivationPath, prelude::SigningKey};
use colored::*;
use console::Term;
use dialoguer::{theme::ColorfulTheme, Select};
use ethers::core as ethers_core;
use ethers::{
    abi::Abi,
    contract::{Contract, Eip712, EthAbiType},
    prelude::{SignerMiddleware, Wallet},
    providers::{Http, Provider},
    signers::{HDPath, Ledger, Signer},
    types::{transaction::eip712::Eip712, Address, H256},
};
use git2::{Oid, Repository};
use std::{
    convert::TryFrom,
    fmt::Debug,
    path::{Path, PathBuf},
};
use zbase32::decode_full_bytes_str;

const NOTES_REF: &str = "refs/notes/radicle/rewards";
const REWARD_ABI: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/abis/RewardV1.json"));
const REWARD_CONTRACT: &str = "0xa6b2337A4e5122Bad631bb6CAbDBB9aa12bb41F6";

/// Puzzle struct
///
/// Defines the data that has to be signed by the corresponding org position,
/// to create the proof to be sended by the contributor to claim the reward.
#[derive(Debug, Clone, Eip712, EthAbiType, serde::Serialize, serde::Deserialize)]
#[eip712(
    name = "Radicle",
    version = "1",
    chain_id = 4,
    verifying_contract = "0xa6b2337A4e5122Bad631bb6CAbDBB9aa12bb41F6"
)]
pub struct Puzzle {
    org: Address,
    contributor: Address,
    commit: [u8; 32],
    project: [u8; 32],
    uri: String,
}

/// Proof, a struct defining the data structure that gets stored in the git notes,
/// with the v, r and s components of the corresponding org.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Proof {
    org: Address,
    contributor: Address,
    commit: [u8; 32],
    project: [u8; 32],
    uri: String,
    v: u8,
    r: [u8; 32],
    s: [u8; 32],
}

pub async fn claim(options: Options) -> anyhow::Result<()> {
    let repo_path = options
        .repo
        .ok_or_else(|| anyhow!(Error::ArgMissing("No repo path specified".into())))?;
    let rpc_url = options
        .rpc_url
        .ok_or_else(|| anyhow!(Error::ArgMissing("No rpc-url specified".into())))?;

    let repo = match Repository::open(repo_path) {
        Ok(repo) => repo,
        Err(e) => bail!("failed to open repo {}", e),
    };
    let provider =
        Provider::<Http>::try_from(rpc_url).expect("could not instantiate HTTP Provider");

    if let Some(keypath) = &options.keystore {
        claim_with_keystore(keypath, repo, provider).await?;
    } else if let Some(path) = &options.ledger_hdpath {
        claim_with_ledger(path, repo, provider).await?;
    } else {
        return Err(anyhow!(Error::ArgMissing(
            "no wallet specified: either '--ledger-hdpath' or '--keystore' must be specified"
                .into()
        )));
    }

    Ok(())
}

pub async fn claim_with_keystore(
    keypath: &Path,
    repo: Repository,
    provider: Provider<Http>,
) -> anyhow::Result<()> {
    let signer = get_keystore(keypath)?;

    let commits = get_eligible_commits(signer.address(), &repo)?;
    let selected_commit = select_commit(&commits)?;
    log::debug!("Selected commit: {:?}", selected_commit);

    let (puzzle, proof) = create_structs(&repo, &selected_commit)?;
    log::debug!("Parsed Puzzle: {:?}", puzzle);

    let signer = SignerMiddleware::new(provider, signer);
    let abi: Abi = serde_json::from_str(REWARD_ABI)?;
    let contract = Contract::new(REWARD_CONTRACT.parse::<Address>().unwrap(), abi, signer);

    let call = contract.method::<_, bool>("claimRewardEOA", (puzzle, proof.v, proof.r, proof.s))?;

    let result = loop {
        let pending = call.send().await?;
        let tx_hash = *pending;

        log::info!("Waiting for transaction {:?} to be included..", tx_hash);

        if let Some(result) = pending.await? {
            break result;
        } else {
            log::info!("Transaction {} dropped, retrying..", tx_hash);
        }
    };

    log::info!(
        "Reward successfully minted in block #{} ({})",
        result.block_number.unwrap(),
        result.block_hash.unwrap(),
    );

    Ok(())
}

pub async fn claim_with_ledger(
    path: &DerivationPath,
    repo: Repository,
    provider: Provider<Http>,
) -> anyhow::Result<()> {
    let signer = get_ledger(path).await?;
    let commits = get_eligible_commits(signer.address(), &repo)?;
    let selected_commit = select_commit(&commits)?;
    log::debug!("Selected commit: {:?}", selected_commit);

    let (puzzle, proof) = create_structs(&repo, &selected_commit)?;
    log::debug!("Parsed Puzzle: {:?}", puzzle);

    let signer = SignerMiddleware::new(provider, signer);
    let abi: Abi = serde_json::from_str(REWARD_ABI)?;
    let contract = Contract::new(REWARD_CONTRACT.parse::<Address>().unwrap(), abi, signer);

    let call = contract.method::<_, bool>("claimRewardEOA", (puzzle, proof.v, proof.r, proof.s))?;

    let result = loop {
        let pending = call.send().await?;
        let tx_hash = *pending;

        log::info!("Waiting for transaction {:?} to be included..", tx_hash);

        if let Some(result) = pending.await? {
            break result;
        } else {
            log::info!("Transaction {} dropped, retrying..", tx_hash);
        }
    };

    log::info!(
        "Reward successfully minted in block #{} ({})",
        result.block_number.unwrap(),
        result.block_hash.unwrap(),
    );

    Ok(())
}

/// Opens the repo checks if the passed commit exists on the repo
/// With the commit hash and other params,creates the message
/// The message is getting signed with a Ledger HW or a keystore file.
/// And stored as a git note on the specified commit
pub async fn create(options: Options) -> anyhow::Result<()> {
    let msg;
    let oid = options
        .commit
        .ok_or_else(|| anyhow!(Error::ArgMissing("No commit specified".into())))?;
    let token_uri = options
        .token_uri
        .ok_or_else(|| anyhow!(Error::ArgMissing("No token URI specified".into())))?;
    let contributor = options
        .contributor
        .ok_or_else(|| anyhow!(Error::ArgMissing("No contributor address specified".into())))?;
    let org = options
        .org
        .ok_or_else(|| anyhow!(Error::ArgMissing("No org address specified".into())))?;
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

    if let Some(keypath) = &options.keystore {
        let signer = get_keystore(keypath)?;
        msg = create_puzzle(
            signer,
            org,
            contributor,
            commit.id().to_string(),
            &project,
            &token_uri,
        )
        .await?;
    } else if let Some(path) = &options.ledger_hdpath {
        let signer = get_ledger(path).await?;
        msg = create_puzzle(
            signer,
            org,
            contributor,
            commit.id().to_string(),
            &project,
            &token_uri,
        )
        .await?;
    } else {
        return Err(anyhow!(Error::ArgMissing(
            "no wallet specified: either '--ledger-hdpath' or '--keystore' must be specified"
                .into()
        )));
    }

    let repo_sig = repo.signature()?;
    repo.note(
        &repo_sig,
        &repo_sig,
        Some(NOTES_REF),
        commit.id(),
        &msg,
        true,
    )?;

    log::info!("Proof successfully created and stored on {:?}", commit.id());

    Ok(())
}

fn get_keystore(keystore: &Path) -> anyhow::Result<Wallet<SigningKey>> {
    let prompt = format!("{} Password: ", "??".cyan());
    let password = rpassword::prompt_password_stdout(&prompt)?;
    let signer = ethers::signers::LocalWallet::decrypt_keystore(keystore, password)
        .map_err(|_| anyhow!("keystore decryption failed"))?
        .with_chain_id(4u64);
    Ok(signer)
}

async fn get_ledger(path: &DerivationPath) -> anyhow::Result<Ledger> {
    let hdpath = path.derivation_string();
    let signer = Ledger::new(HDPath::Other(hdpath), 1).await?;

    Ok(signer)
}

async fn create_puzzle<S: Signer>(
    signer: S,
    org: Address,
    contributor: Address,
    commit: String,
    project: &str,
    uri: &str,
) -> anyhow::Result<String> {
    let mut project_vec = decode_full_bytes_str(project).unwrap();
    project_vec.resize(32, 0);
    let project = H256::from_slice(&project_vec);

    let commit = convert_hex_to_fixed_bytes32(commit)?;

    // Instantiate of puzzle
    let puzzle = Puzzle {
        org,
        contributor,
        commit: commit.to_fixed_bytes(),
        project: project.to_fixed_bytes(),
        uri: uri.to_string(),
    };

    let sig = signer
        .sign_typed_data(&puzzle)
        .await
        .map_err(|_| anyhow!(Error::SignFailure))?;

    let r = <[u8; 32]>::try_from(sig.r)
        .expect("failed to parse 'r' value from signature into [u8; 32]");
    let s = <[u8; 32]>::try_from(sig.s)
        .expect("failed to parse 's' value from signature into [u8; 32]");
    let v = u8::try_from(sig.v).expect("failed to parse 'v' value from signature into u8");

    // Creation of proof json
    serde_json::to_string(&Proof {
        org,
        contributor,
        commit: commit.to_fixed_bytes(),
        project: project.to_fixed_bytes(),
        uri: uri.to_string(),
        v,
        r,
        s,
    })
    .map_err(|_| anyhow!(Error::SerializeFailure))
}

fn convert_hex_to_fixed_bytes32(input: String) -> anyhow::Result<H256> {
    let mut vec = hex::decode(input)?;
    vec.resize(32, 0);
    Ok(H256::from_slice(&vec))
}

pub fn create_structs(repo: &Repository, selected_commit: &Oid) -> anyhow::Result<(Puzzle, Proof)> {
    let note = repo.find_note(Some(NOTES_REF), *selected_commit)?;
    log::debug!("Selected note: {:?}", note.id());

    let note = match note.message() {
        Some(proof) => proof,
        None => bail!("Not able to obtain commit message"),
    };

    let proof: Proof = serde_json::from_str(note)?;
    log::debug!("Retrieved Proof: {:?}", proof);

    let puzzle = Puzzle {
        org: proof.org,
        contributor: proof.contributor,
        commit: proof.commit,
        project: proof.project,
        uri: proof.uri.clone(),
    };

    Ok((puzzle, proof))
}

pub fn select_commit(commits: &[Oid]) -> anyhow::Result<Oid> {
    let selection = Select::with_theme(&ColorfulTheme::default())
        .items(commits)
        .with_prompt("Claimable Commits")
        .interact_on_opt(&Term::stderr())?;

    let index = match selection {
        Some(index) => index,
        None => bail!("User did not select any commit"),
    };

    Ok(commits[index])
}

pub fn get_eligible_commits(
    signer_address: Address,
    repo: &Repository,
) -> anyhow::Result<Vec<Oid>> {
    let mut commits: Vec<Oid> = Vec::new();

    for note in repo.notes(Some(NOTES_REF))? {
        let oids = note?;
        let note = repo.find_note(Some(NOTES_REF), oids.1)?;
        let message = note.message().unwrap();
        let t: Proof = serde_json::from_str(message)?;
        if signer_address == t.contributor {
            commits.push(oids.1);
        }
    }

    Ok(commits)
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
    pub org: Option<Address>,
    /// Address of contributor
    pub contributor: Option<Address>,
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
    /// Token URI of proof to sign
    pub token_uri: Option<String>,
    /// RPC url
    pub rpc_url: Option<String>,
}
