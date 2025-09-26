//! Proving pipeline that orchestrates the full proving process

use super::engine::ProvingEngine;
use super::input::InputParser;
use super::types::ProverError;
use crate::{ analytics::track_verification_failed, prover::input };
use crate::environment::Environment;
use crate::task::Task;
use chrono::Local;
use futures::stream::FuturesUnordered;
use nexus_sdk::stwo::seq::Proof;
use rayon::iter::IntoParallelRefIterator;
use sha3::{ Digest, Keccak256 };
use tokio::task;
use std::collections::HashSet;
use std::iter;
use std::sync::atomic::{ AtomicUsize, Ordering };
use std::sync::Arc;
use tokio::sync::Semaphore;
use futures::stream::StreamExt;
/// Orchestrates the complete proving pipeline
pub struct ProvingPipeline;

impl ProvingPipeline {
    /// Execute authenticated proving for a task
    pub async fn prove_authenticated(
        task: &Task,
        environment: &Environment,
        client_id: &str,
        num_workers: usize,
        with_local: bool
    ) -> Result<(Vec<Proof>, String, Vec<String>), ProverError> {
        match task.program_id.as_str() {
            "fib_input_initial" =>
                Self::prove_fib_task(task, environment, client_id, num_workers, with_local).await,
            _ =>
                Err(
                    ProverError::MalformedTask(
                        format!("Unsupported program ID: {}", task.program_id)
                    )
                ),
        }
    }

    // Process fibonacci proving task with multiple inputs
    async fn prove_fib_task_single(
        task: &Task,
        environment: &Environment,
        client_id: &str,
        with_local: bool
    ) -> Result<(Vec<Proof>, String, Vec<String>), ProverError> {
        let all_inputs = task.all_inputs();

        if all_inputs.is_empty() {
            return Err(ProverError::MalformedTask("No inputs provided for task".to_string()));
        }

        let mut proof_hashes = Vec::new();
        let mut all_proofs: Vec<Proof> = Vec::new();

        for (input_index, input_data) in all_inputs.iter().enumerate() {
            // Step 1: Parse and validate input
            let inputs = InputParser::parse_triple_input(input_data)?;
            // Step 2: Generate and verify proof
            let proof = ProvingEngine::prove_and_validate(
                &inputs,
                task,
                environment,
                client_id,
                false,
                input_index
            ).await.map_err(|e| {
                match e {
                    ProverError::Stwo(_) | ProverError::GuestProgram(_) => {
                        // Track verification failure
                        let error_msg = format!("Input {}: {}", input_index as u32, e);
                        tokio::spawn(
                            track_verification_failed(
                                task.clone(),
                                error_msg.clone(),
                                environment.clone(),
                                client_id.to_string()
                            )
                        );
                        e
                    }
                    _ => e,
                }
            })?;

            // Step 3: Generate proof hash
            let proof_hash = Self::generate_proof_hash(&proof);
            proof_hashes.push(proof_hash);
            all_proofs.push(proof);
        }

        let final_proof_hash = Self::combine_proof_hashes(task, &proof_hashes);

        Ok((all_proofs, final_proof_hash, proof_hashes))
    }

    /// Process fibonacci proving task with multiple inputs
    async fn prove_fib_task(
        task: &Task,
        environment: &Environment,
        client_id: &str,
        num_workers: usize,
        with_local: bool
    ) -> Result<(Vec<Proof>, String, Vec<String>), ProverError> {
        let all_inputs = task.all_inputs();
        let len = all_inputs.len();
        if num_workers == 1 {
            println!("num_workers: {}, all_inputs.len: {}", num_workers, all_inputs.len());
            return Self::prove_fib_task_single(task, environment, client_id, with_local).await;
        }
        if all_inputs.is_empty() {
            return Err(ProverError::MalformedTask("No inputs provided for task".to_string()));
        }
        println!("num_workers: {}, all_inputs.len: {}", num_workers, all_inputs.len());
        // 检查是否有重复
        let mut seen = HashSet::new();
        for input in all_inputs {
            if !seen.insert(input) {
                // insert 返回 false 表示已存在
                println!("input has same item");
            }
        }
        let semaphore = Arc::new(Semaphore::new(num_workers));
        let completed = Arc::new(AtomicUsize::new(0)); // ✅ 进度计数器
        let next_report_percent = Arc::new(AtomicUsize::new(5)); // 从 5% 开始
        let mut futures = FuturesUnordered::new();
        println!(
            "[{}] [{}/{}] {}% of proofs completed",
            Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            0,
            len,
            0
        );
        for (input_index, input_data) in all_inputs.iter().enumerate() {
            let permit = semaphore
                .clone()
                .acquire_owned().await
                .map_err(|_| { ProverError::MalformedTask("Semaphore closed".into()) })?;

            let task = task.clone();
            let env = environment.clone();
            let client_id = client_id.to_string();
            let input_data = input_data.clone();
            let completed = completed.clone(); // 共享计数器

            let fut = async move {
                let _permit = permit; // held until end of block
                let inputs = InputParser::parse_triple_input(&input_data)?;
                let proof = ProvingEngine::prove_and_validate(
                    &inputs,
                    &task,
                    &env,
                    &client_id,
                    false,
                    input_index
                ).await?;

                let hash = Self::generate_proof_hash(&proof);

                Ok::<_, ProverError>((input_index, proof, hash))
            };
            let current_completed = completed.fetch_add(1, Ordering::Relaxed) + 1;
            let current_percent = (current_completed * 100) / len;

            let mut report_threshold = next_report_percent.load(Ordering::Relaxed);
            while current_percent >= report_threshold && report_threshold <= 100 {
                if
                    next_report_percent
                        .compare_exchange_weak(
                            report_threshold,
                            report_threshold + 5,
                            Ordering::Relaxed,
                            Ordering::Relaxed
                        )
                        .is_ok()
                {
                    println!(
                        "[{}] [{}/{}] {}% of proofs completed",
                        Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                        current_completed,
                        len,
                        report_threshold
                    );
                    break;
                }
                report_threshold = next_report_percent.load(Ordering::Relaxed);
            }
            futures.push(tokio::spawn(fut));
        }

        let mut results: Vec<Option<(usize, Proof, String)>> = iter
            ::repeat_with(|| None)
            .take(all_inputs.len())
            .collect();

        while let Some(result) = futures.next().await {
            match result {
                Ok(Ok((idx, proof, hash))) => {
                    results[idx] = Some((idx, proof, hash));
                }
                Ok(Err(e)) => {
                    // 可选择立即返回或收集错误
                    // 这里我们选择 fail-fast
                    return Err(ProverError::MalformedTask("Task panicked".into()));
                }
                Err(_) => {
                    return Err(ProverError::MalformedTask("Task panicked".into()));
                }
            }
        }

        // 按顺序提取
        let (mut all_proofs, mut proof_hashes) = (Vec::new(), Vec::new());
        for res in results.into_iter() {
            if let Some((_, proof, hash)) = res {
                all_proofs.push(proof);
                proof_hashes.push(hash);
            }
        }

        let final_hash = Self::combine_proof_hashes(task, &proof_hashes);
        Ok((all_proofs, final_hash, proof_hashes))
    }

    /// Generate hash for a proof
    pub fn generate_proof_hash(proof: &Proof) -> String {
        let proof_bytes = postcard::to_allocvec(proof).expect("Failed to serialize proof");
        format!("{:x}", Keccak256::digest(&proof_bytes))
    }

    /// Combine multiple proof hashes based on task type
    fn combine_proof_hashes(task: &Task, proof_hashes: &[String]) -> String {
        match task.task_type {
            | crate::nexus_orchestrator::TaskType::AllProofHashes
            | crate::nexus_orchestrator::TaskType::ProofHash => {
                Task::combine_proof_hashes(proof_hashes)
            }
            _ => proof_hashes.first().cloned().unwrap_or_default(),
        }
    }
}
