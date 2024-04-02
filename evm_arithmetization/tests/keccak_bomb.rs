use std::str::FromStr;
use std::time::Duration;

use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::{Address, BigEndianHash, H256, U256};
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::prover::prove;
use evm_arithmetization::prover::testing::simulate_execution;
use evm_arithmetization::verifier::verify_proof;
use evm_arithmetization::{AllStark, Node, StarkConfig};
use hex_literal::hex;
use keccak_hash::keccak;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::KeccakGoldilocksConfig;
use plonky2::util::timing::TimingTree;

type F = GoldilocksField;
const D: usize = 2;
type C = KeccakGoldilocksConfig;

/// Keccak bomb contract to stress test the prover.
#[test]
fn test_keccak_bomb() -> anyhow::Result<()> {
    init_logger();

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    let beneficiary = hex!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    let sender = hex!("CAC88047981018cA012b4b55F64Ebf0dddA045dC");
    // Private key:
    // `ba51377a7ae22c3c5e61393b9d8f4799307662a4458d55f4d3f78f913f1888fc`
    let contract = hex!("5FbDB2315678afecb367f032d93F642f64180aa3");

    let sender_state_key = keccak(sender);
    let contract_state_key = keccak(contract);

    let sender_nibbles = Nibbles::from_bytes_be(sender_state_key.as_bytes()).unwrap();
    let contract_nibbles = Nibbles::from_bytes_be(contract_state_key.as_bytes()).unwrap();

    let sender_account = AccountRlp {
        nonce: 0.into(),
        balance: sd2u("10000000000000000000000"),
        storage_root: Default::default(),
        code_hash: keccak([]),
    };

    let contract_account = AccountRlp {
        nonce: 0.into(),
        balance: 0.into(),
        storage_root: Default::default(),
        code_hash: keccak(contract_bytecode()),
    };

    let mut state_trie_before = HashedPartialTrie::from(Node::Empty);
    state_trie_before.insert(sender_nibbles, rlp::encode(&sender_account).to_vec());
    state_trie_before.insert(contract_nibbles, rlp::encode(&contract_account).to_vec());

    let tries_before = TrieInputs {
        state_trie: state_trie_before,
        transactions_trie: HashedPartialTrie::from(Node::Empty),
        receipts_trie: HashedPartialTrie::from(Node::Empty),
        storage_tries: vec![],
    };

    let gas_used = 40306029;
    let txn = signed_tx();

    let block_metadata = BlockMetadata {
        block_beneficiary: Address::from(beneficiary),
        block_timestamp: 0x03e8.into(),
        block_number: 1.into(),
        block_difficulty: 0x020000.into(),
        block_random: H256::from_uint(&0x020000.into()),
        block_gaslimit: 0xffffffffu32.into(),
        block_chain_id: 1.into(),
        block_base_fee: 0xa.into(),
        block_gas_used: gas_used.into(),
        block_bloom: [0.into(); 8],
    };

    let contract_code = [contract_bytecode(), vec![]]
        .map(|v| (keccak(v.clone()), v))
        .into();

    let expected_state_trie_after: HashedPartialTrie = {
        let mut state_trie_after = HashedPartialTrie::from(Node::Empty);
        let sender_account_after = AccountRlp {
            nonce: sender_account.nonce + 1,
            balance: sender_account.balance - U256::from(gas_used) * 0xa,
            ..sender_account
        };
        state_trie_after.insert(sender_nibbles, rlp::encode(&sender_account_after).to_vec());
        state_trie_after.insert(contract_nibbles, rlp::encode(&contract_account).to_vec());

        state_trie_after
    };

    let receipt_0 = LegacyReceiptRlp {
        status: true,
        cum_gas_used: gas_used.into(),
        bloom: vec![0; 256].into(),
        logs: vec![],
    };
    let mut receipts_trie = HashedPartialTrie::from(Node::Empty);
    receipts_trie.insert(Nibbles::from_str("0x80").unwrap(), receipt_0.encode(2));
    let transactions_trie: HashedPartialTrie = Node::Leaf {
        nibbles: Nibbles::from_str("0x80").unwrap(),
        value: txn.to_vec(),
    }
    .into();

    let trie_roots_after = TrieRoots {
        state_root: expected_state_trie_after.hash(),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };

    let inputs = GenerationInputs {
        signed_txn: Some(txn.to_vec()),
        withdrawals: vec![],
        tries: tries_before,
        trie_roots_after,
        contract_code,
        checkpoint_state_trie_root: HashedPartialTrie::from(Node::Empty).hash(),
        block_metadata,
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: gas_used.into(),
        block_hashes: BlockHashes {
            prev_hashes: vec![H256::default(); 256],
            cur_hash: H256::default(),
        },
    };

    let timing = TimingTree::new("simulate", log::Level::Debug);
    simulate_execution::<F>(inputs)?;
    timing.filter(Duration::from_millis(100)).print();

    Ok(())
}

fn sd2u(s: &str) -> U256 {
    U256::from_dec_str(s).unwrap()
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
}

fn contract_bytecode() -> Vec<u8> {
    hex!("608060405234801561000f575f80fd5b5060043610610029575f3560e01c8063dd3cad3d1461002d575b5f80fd5b610047600480360381019061004291906100d6565b610049565b005b5f805f1b90505f5b8281101561009a575f8260405160200161006b919061012a565b60405160208183030381529060405290508080519060200120925050808061009290610171565b915050610051565b505050565b5f80fd5b5f819050919050565b6100b5816100a3565b81146100bf575f80fd5b50565b5f813590506100d0816100ac565b92915050565b5f602082840312156100eb576100ea61009f565b5b5f6100f8848285016100c2565b91505092915050565b5f819050919050565b5f819050919050565b61012461011f82610101565b61010a565b82525050565b5f6101358284610113565b60208201915081905092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f61017b826100a3565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82036101ad576101ac610144565b5b60018201905091905056fea264697066735822122097a946ae280766a9002c919252c4ac62cbf04e9581076135efdf5c0124399db664736f6c63430008150033").into()
}

fn signed_tx() -> Vec<u8> {
    hex!("f885800a84ffffffff945fbdb2315678afecb367f032d93f642f64180aa380a4dd3cad3d000000000000000000000000000000000000000000000000000000000000b79426a00d4b9ed99907cba5a63ef3943adc9bb452a10998aca8122fd976a65609d28387a012bc9faf09e1a084f91bbd67b8a41e26a1497598c9bfdd8d68c3af8086f92f7a").into()
}
