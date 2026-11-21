//! Dry-run wallet sanity check against a live Gnosis RPC.
//!
//! Reads the configured wallet's address + nonce from the chain and
//! prints a fully-signed (but **not submitted**) `topUp(batchId, 0)`
//! transaction so the operator can verify
//!
//!   - the keystore loads cleanly,
//!   - the derived Ethereum address matches what's on the chain,
//!   - calldata + RLP encoding is byte-correct,
//!
//! without spending any xDAI or BZZ.
//!
//! Usage:
//!
//! ```text
//! GNOSIS_RPC_URL=... \
//! POSTAGE_OWNER_KEY=0x...32-byte hex... \
//! POSTAGE_CONTRACT=0x45a1502382541Cd610CC9068e88727426b696293 \
//! STORAGE_STAMP_BATCH_ID=0x...32-byte hex... \
//! cargo run --example dry_run_wallet -p ant-chain
//! ```

use std::env;

use ant_chain::tx::{
    postage_top_up_calldata, sign_legacy_tx, LegacyTx, Wallet, DEFAULT_GAS_PRICE_WEI,
    GNOSIS_CHAIN_ID, POSTAGE_TOP_UP_GAS,
};
use ant_chain::ChainClient;
use primitive_types::U256;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::var("GNOSIS_RPC_URL")?;
    let key_hex =
        env::var("POSTAGE_OWNER_KEY").or_else(|_| env::var("STORAGE_STAMP_PRIVATE_KEY"))?;
    let postage = env::var("POSTAGE_CONTRACT")?;
    let batch_hex = env::var("STORAGE_STAMP_BATCH_ID")?;

    let mut secret = [0u8; 32];
    let strip = |s: &str| -> String {
        s.strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s)
            .to_string()
    };
    hex::decode_to_slice(strip(&key_hex), &mut secret)?;
    let mut postage_addr = [0u8; 20];
    hex::decode_to_slice(strip(&postage), &mut postage_addr)?;
    let mut batch_id = [0u8; 32];
    hex::decode_to_slice(strip(&batch_hex), &mut batch_id)?;

    let client = ChainClient::new(url);
    let wallet = Wallet::new(secret, GNOSIS_CHAIN_ID)?;
    println!("wallet address: 0x{}", hex::encode(wallet.address()));

    let nonce = client
        .eth_get_transaction_count_pending(wallet.address())
        .await?;
    println!("pending nonce:  {nonce}");

    let calldata = postage_top_up_calldata(&batch_id, &U256::from(0u64));
    let tx = LegacyTx {
        nonce,
        gas_price_wei: DEFAULT_GAS_PRICE_WEI,
        gas_limit: POSTAGE_TOP_UP_GAS,
        to: postage_addr,
        value_wei: U256::zero(),
        data: calldata,
        chain_id: GNOSIS_CHAIN_ID,
    };
    let (raw, hash) = sign_legacy_tx(&secret, &tx)?;
    println!("would-be tx hash: 0x{}", hex::encode(hash));
    println!("raw tx ({} bytes): 0x{}", raw.len(), hex::encode(raw));
    println!("(not submitted; this example is read-only)");
    Ok(())
}
