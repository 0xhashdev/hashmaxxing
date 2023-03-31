use std::path::Path;

use std::process;

use eth_keystore::{encrypt_key, decrypt_key};

use crate::helpers::*;

use colored::*;

use ethers::{
    prelude::*,
    abi::Abi,
    contract::Contract,
    providers::Provider
};

use serde_json;

pub fn get_privkey_from_path(keypath: &Path, password: &str) -> [u8; 32] {
    let mut private_key: [u8; 32];
    match decrypt_key(&keypath, password.clone()) {
        Ok(privkey) => {
            match privkey.into_iter().take(32).collect::<Vec<u8>>().try_into() {
                Ok(array) => {
                    private_key = array; 
                },
                Err(convert_error) => {
                    eprintln!("{}", format!("Error getting private key from {}: {:?}",  keypath.to_str().unwrap(), convert_error).red().bold());
                    process::exit(0x01);
                } 
            }
        }
        Err(error) => {
            eprintln!("{}", format!("Error getting private key from {}: {:?}", keypath.to_str().unwrap(), error).red().bold());
            process::exit(0x01);
        } 
    }

    return private_key;
}

pub fn create_wallet(private_key: [u8; 32], chain_id: u64) -> ethers::signers::Wallet<ethers::core::k256::ecdsa::SigningKey> {
    return bytes2hex(private_key)[2..].parse::<LocalWallet>().unwrap().with_chain_id( chain_id );
}

pub fn get_provider(rpc_url: &str) -> Provider<Http> {
    return Provider::<Http>::try_from( rpc_url ).unwrap();
            
}

pub fn instantiate_client(privkey: [u8; 32], chain_id: u64, rpc_url: &str) -> ethers::middleware::signer::SignerMiddleware<Provider<Http>, ethers::signers::Wallet<ethers::core::k256::ecdsa::SigningKey>> {
    // let privkey = get_privkey_from_path(keypath, password);
    let wallet = create_wallet(privkey, chain_id);
    let provider = get_provider(rpc_url).with_sender(wallet.address());

    return SignerMiddleware::new(
        provider.clone(), 
        wallet.clone()
    );
}

pub fn instantiate_contract(address: &str, abi: &str, provider: Provider<Http>) -> Contract<Provider<Http>> {
    let _abi: Abi = serde_json::from_str(abi).unwrap();
    return Contract::new(
        address.parse::<Address>().unwrap(),
        _abi,
        provider.clone()
    );
}