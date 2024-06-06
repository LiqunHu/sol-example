#![cfg(feature = "test-bpf")]
use {
    borsh::{to_vec, BorshDeserialize},
    secp256k1::{rand::rngs::OsRng, Message, Secp256k1},
    solana_program::instruction::{AccountMeta, Instruction},
    solana_program_test::*,
    solana_sdk::{
        account::Account, keccak, secp256k1_recover::secp256k1_recover, signature::Signer,
        signer::keypair::Keypair, system_program, transaction::Transaction,
    },
    zkpass_airdrop_attestation::state::{Attest, AttestationRequest, ExampleDataV1, Task},
};

#[tokio::test]
async fn test() {
    let program_id = Pubkey::new_unique();
    let notary_account = Keypair::new();

    let secp = Secp256k1::new();
    let (allocator_secret_key, allocator_public_key) = secp.generate_keypair(&mut OsRng);
    let (notary_secret_key, notary_public_key) = secp.generate_keypair(&mut OsRng);

    let (data_account_key, _) = Pubkey::find_program_address(&["example".as_bytes()], &program_id);

    let mut program_test = ProgramTest::new("example", program_id, processor!(process_instruction));
    program_test.add_account(
        notary_account.pubkey(),
        Account {
            lamports: 50000000,
            ..Account::default()
        },
    );

    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    let notary =
        hex::encode(keccak::hashv(&[&notary_public_key.serialize_uncompressed()[1..]]).as_ref());
    let allocator =
        hex::encode(keccak::hashv(&[&allocator_public_key.serialize_uncompressed()[1..]]).as_ref());

    let mut attest = AttestationRequest {
        task: "0x3837396435313738613434363464666438373035636465636339326662623030".to_string(),
        schema: "e504ad91fbaad88362941a65b1c4c1e1cdd5cf69e27a3a08c8f51145c2e12c6a".to_string(),
        nullifier: "0xf1dc22f28f20a336838d91aea3da6749ccc0cd3ef5e985c2dd0788b310734dab".to_string(),
        recipient: "CbtxDcg4jPUCCuf5smF9kUUS1MTXchcJA2ggK1x4pa5A".to_string(),
        public_fields_hash: "9dNsQaHyWg9c4jURSdvP9RxfEtBVN7Xh4sypL3kMH81B".to_string(),
        a_recovery_id: 0,
        a_signature: [0; 64],
        n_recovery_id: 0,
        n_signature: [0; 64],
        notary: notary.clone(),
        allocator: allocator.clone(),
    };

    let task = Task {
        task: attest.task.clone(),
        schema: attest.schema.clone(),
        notary: notary.clone(),
    };
    let msg_hash = keccak::hashv(&[&to_vec(&task).unwrap()]);
    let message = Message::from_digest_slice(&msg_hash.as_ref()).unwrap();
    let signature = secp.sign_ecdsa_recoverable(&message, &allocator_secret_key);
    let (recovery_id, serialize_sig) = signature.serialize_compact();

    let res = secp256k1_recover(
        msg_hash.as_ref(),
        recovery_id.to_i32() as u8,
        serialize_sig.as_ref(),
    )
    .unwrap();
    println!(
        "!!!{:?}",
        hex::encode(keccak::hashv(&[res.0.as_ref()]).as_ref())
    );

    attest.a_recovery_id = recovery_id.to_i32() as u8;

    attest.a_signature = serialize_sig;

    let at = Attest {
        task: attest.task.clone(),
        schema: attest.schema.clone(),
        nullifier: attest.nullifier.clone(),
        recipient: attest.recipient.clone(),
        public_fields_hash: attest.public_fields_hash.clone(),
    };
    let msg_hash = keccak::hashv(&[&to_vec(&at).unwrap()]);
    let message = Message::from_digest_slice(&msg_hash.as_ref()).unwrap();
    let signature = secp.sign_ecdsa_recoverable(&message, &notary_secret_key);
    let (recovery_id, serialize_sig) = signature.serialize_compact();
    attest.n_recovery_id = recovery_id.to_i32() as u8;

    attest.n_signature = serialize_sig;

    let transaction = Transaction::new_signed_with_payer(
        &[Instruction::new_with_borsh(
            program_id,
            &ExampleInstruction::Attest(attest),
            vec![
                AccountMeta::new(payer.pubkey(), true),            // payer
                AccountMeta::new(data_account_key.clone(), false), // data
                AccountMeta::new_readonly(system_program::id(), false),
            ],
        )],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    let res = banks_client
        .process_transaction_with_metadata(transaction)
        .await
        .unwrap();

    let data = match banks_client
        .get_account(data_account_key.clone())
        .await
        .unwrap()
    {
        Some(account) => ExampleDataV1::try_from_slice(&account.data).unwrap(),
        None => panic!(),
    };
    println!("{:?}", data.attest);
}
