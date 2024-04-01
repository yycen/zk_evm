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

    let gas_used: u32 = 0xFFFFFFFF;
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

        state_trie_after
    };

    let receipt_0 = LegacyReceiptRlp {
        status: false,
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
    hex!("608060405234801561000f575f80fd5b506004361061004a575f3560e01c8063ae4e34001461004e578063c4b05f841461006a578063d52472f514610086578063dd3cad3d146100a2575b5f80fd5b61006860048036038101906100639190610327565b6100be565b005b610084600480360381019061007f9190610327565b610145565b005b6100a0600480360381019061009b9190610327565b6101a5565b005b6100bc60048036038101906100b79190610327565b610263565b005b5f805f1b6040516020016100d2919061037b565b60405160208183030381529060405290505f5b82811015610109578180519060200120508080610101906103c2565b9150506100e5565b507f04533159d8081fe24bc5fe2be8f93f2b562d92255fcdf8a09441605e3e11f49f826040516101399190610418565b60405180910390a15050565b5f805f1b90503d60015f5b848110156101675781832093508181019050610150565b5050507f02e4f1f741a8b106bf9129c4b006a584481f84f330bdb97a4e7ff8445e335c45816040516101999190610440565b60405180910390a15050565b5f805f805f805f805f805f60015f5b8d81101561020a5760015f209c50600180209b5060016002209a506001600320995060016004209850600160052097506001600620965060016007209550600160082094506001600920935081810190506101b4565b5050507f5c061f3eb26904c7293c922811455ef53a1e04a05ac99fa47001a2315e0a204d8a8a8a8a8a8a8a8a8a8a60405161024e9a99989796959493929190610459565b60405180910390a15050505050505050505050565b5f805f1b90505f5b828110156102b4575f82604051602001610285919061037b565b6040516020818303038152906040529050808051906020012092505080806102ac906103c2565b91505061026b565b507f02e4f1f741a8b106bf9129c4b006a584481f84f330bdb97a4e7ff8445e335c45816040516102e49190610440565b60405180910390a15050565b5f80fd5b5f819050919050565b610306816102f4565b8114610310575f80fd5b50565b5f81359050610321816102fd565b92915050565b5f6020828403121561033c5761033b6102f0565b5b5f61034984828501610313565b91505092915050565b5f819050919050565b5f819050919050565b61037561037082610352565b61035b565b82525050565b5f6103868284610364565b60208201915081905092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6103cc826102f4565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82036103fe576103fd610395565b5b600182019050919050565b610412816102f4565b82525050565b5f60208201905061042b5f830184610409565b92915050565b61043a81610352565b82525050565b5f6020820190506104535f830184610431565b92915050565b5f6101408201905061046d5f83018d610431565b61047a602083018c610431565b610487604083018b610431565b610494606083018a610431565b6104a16080830189610431565b6104ae60a0830188610431565b6104bb60c0830187610431565b6104c860e0830186610431565b6104d6610100830185610431565b6104e4610120830184610431565b9b9a505050505050505050505056fea2646970667358221220ebd3f3e188fd1fc6870d7cfa2a44be53e49598298664e6e13e0130356f43f04264736f6c63430008150033").into()
}

fn signed_tx() -> Vec<u8> {
    hex!("f885800a84ffffffff945fbdb2315678afecb367f032d93f642f64180aa380a4dd3cad3d000000000000000000000000000000000000000000000000000000000000b79426a00d4b9ed99907cba5a63ef3943adc9bb452a10998aca8122fd976a65609d28387a012bc9faf09e1a084f91bbd67b8a41e26a1497598c9bfdd8d68c3af8086f92f7a").into()
}
