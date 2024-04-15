use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::Result;
use ciborium_io::Write;
use ethers::prelude::*;

use proof_gen::proof_gen::generate_txn_proof;
use proof_gen::prover_state::ProverStateBuilder;

use crate::utils::gather_witness;

mod mpt;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    let proof_gen_ir;
    if Path::new("../test_witness.json").exists() {
        println!("reading from test_witness.json...");
        let mut file = File::open("../test_witness.json")?;
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)?;
        println!("witness length: {}", buffer.len());
        proof_gen_ir = serde_json::from_str(&buffer)?;
    } else {
        println!("test_witness.json not exist, get witness from RPC...");
        let provider = Provider::<Http>::try_from(
            "https://opbnb-testnet.nodereal.io/v1/<your_key>"
        ).expect("could not instantiate HTTPs Provider");
        let tx_hash: TxHash = "0xca70656217989acbbf3c45442b7b6011e9872e9f4a72e33126512e607ca065c1".parse().unwrap();
        proof_gen_ir = gather_witness(tx_hash, &provider).await?;
        // std::io::stdout().write_all(&serde_json::to_vec(&gen_inputs)?)?;
        let mut file = File::create("../test_witness.json")?;
        file.write_all(&serde_json::to_vec(&proof_gen_ir)?)?;
    }

    let builder = ProverStateBuilder::default();
    // let builder = builder
    // .set_arithmetic_circuit_size(16..23)
    // .set_byte_packing_circuit_size(9..21)
    // .set_cpu_circuit_size(12..25)
    // .set_keccak_circuit_size(14..20)
    // .set_keccak_sponge_circuit_size(9..15)
    // .set_logic_circuit_size(12..18)
    // .set_memory_circuit_size(17..28);
    let prover_state = builder.build();
    for (i, input) in proof_gen_ir.iter().enumerate() {
        println!("Proving tx {}", i);
        if let Err(error) = generate_txn_proof(&prover_state, input.clone(), None) {
            println!("Error proving tx: {:?}", error);
        }
    }
    println!("finished");

    Ok(())
}