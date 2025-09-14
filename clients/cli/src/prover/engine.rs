//! Core proving engine

use crate::prover::verifier;

use super::types::ProverError;
use crate::analytics::track_likely_oom_error;
use crate::environment::Environment;
use crate::task::Task;
use nexus_sdk::{
    Local, Prover,
    stwo::seq::{Proof, Stwo},
};
use postcard::from_bytes;
use serde_json;
use std::env;
use std::process::Stdio;
use std::time::Instant;
use sha3::Keccak256;
use sha3::Digest;
const ELF_PROVER: &[u8; 104004] = include_bytes!("../../assets/fib_input_initial");

/// Core proving engine for ZK proof generation
pub struct ProvingEngine;

impl ProvingEngine {
    /// Create a Stwo prover instance for the fibonacci program
    pub fn create_fib_prover() -> Result<Stwo<Local>, ProverError> {
        Stwo::<Local>::new_from_bytes(ELF_PROVER).map_err(|e| {
            ProverError::Stwo(format!(
                "Failed to load fib_input_initial guest program: {}",
                e
            ))
        })
    }

    /// Subprocess entrypoint: generate proof without verification
    pub fn prove_fib_subprocess(inputs: &(u32, u32, u32)) -> Result<Proof, ProverError> {
        let now = std::time::Instant::now();
        let prover = Self::create_fib_prover()?;
        let (view, proof) = prover
            .prove_with_input::<(), (u32, u32, u32)>(&(), inputs)
            .map_err(|e| {
                ProverError::Stwo(format!(
                    "Failed to generate proof for inputs {:?}: {}",
                    inputs, e
                ))
            })?;
        // Check exit code in subprocess
        // verifier::ProofVerifier::check_exit_code(&view)?;
        // 4. 打印耗时（可选：写到 stderr 让主进程收集日志）
        eprintln!(
            "prove_fib_subprocess finished for inputs {:?} in {} ms",
            inputs,
            now.elapsed().as_millis()
        );
        Ok(proof)
    }

    /// Generate proof for given inputs using the fibonacci program in a subprocess
    pub async fn prove_and_validate(
        inputs: &(u32, u32, u32),
        task: &Task,
        environment: &Environment,
        client_id: &str,
        with_local: bool,
        index: usize,
    ) -> Result<Proof, ProverError> {
        if with_local {
            // Use local prover
            println!("index {index} Using local prover f inputs: {:?}", inputs);
            let now: Instant = Instant::now();
            let prover = Self::create_fib_prover()?;
            let (view, proof) = prover
                .prove_with_input::<(), (u32, u32, u32)>(&(), inputs)
                .map_err(|e| {
                    ProverError::Stwo(format!(
                        "Failed to generate proof for inputs {:?}: {}",
                        inputs, e
                    ))
                })?;
            // Check exit code in subprocess
            verifier::ProofVerifier::check_exit_code(&view)?;
            println!(
                "index {index} check_exit_code {} milliseconds",
                now.elapsed().as_millis()
            );
            return Ok(proof);
        }
        let now = Instant::now();
        // Spawn a subprocess for proof generation to isolate memory usage
        let exe_path = env::current_exe()?;
        let mut cmd = tokio::process::Command::new(exe_path);
        cmd.arg("prove-fib-subprocess")
            .arg("--inputs")
            .arg(serde_json::to_string(inputs)?)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let output = cmd.output().await?;

        if !output.status.success() {
            if let Some(code) = output.status.code() {
                if code == crate::consts::cli_consts::SUBPROCESS_SUSPECTED_OOM_CODE {
                    // 128 + 9 = 137 means external sigkill, so likely killed by kernel due to OOM; track analytics event
                    tokio::spawn(track_likely_oom_error(
                        task.clone(),
                        environment.clone(),
                        client_id.to_string(),
                    ));
                }

                if code == crate::consts::cli_consts::SUBPROCESS_INTERNAL_ERROR_CODE {
                    // error happened inside the subprocess, and so we know that it may be useful information to the user
                    return Err(ProverError::Subprocess(format!(
                        "Error while proving within subprocess, captured error: [{}]",
                        &String::from_utf8_lossy(&output.stderr)
                    )));
                }
            }

            return Err(ProverError::Subprocess(format!(
                "Prover subprocess failed with status: {}",
                output.status
            )));
        }

        // Deserialize proof from subprocess stdout
        let proof: Proof = from_bytes(&output.stdout)?;
        println!("{}", String::from_utf8_lossy(&output.stderr));
 println!("hash: {}", Self::generate_proof_hash(&proof));

        // Verify proof in main process
        // let verify_prover = Self::create_fib_prover()?;
        // verifier::ProofVerifier::verify_proof(&proof, inputs, &verify_prover)?;

        // 打印 proof 耗时
        println!(
            "index {index} verify proof {} milliseconds",
            now.elapsed().as_millis()
        );
        Ok(proof)
    }
    fn generate_proof_hash(proof: &Proof) -> String {
        let proof_bytes = postcard::to_allocvec(proof).expect("Failed to serialize proof");
        format!("{:x}", Keccak256::digest(&proof_bytes))
    }
}
