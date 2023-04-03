
use web3_hash_utils::keccak256;
use web3::types::*;

use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use rand::{Rng, thread_rng};
use rand::prelude::*;

use crate::helpers::*;


pub fn pack_byte_arrays(nonce_count_hash: [u8; 32], chain_id_hash: [u8; 32], beneficiary: [u8; 20], nonce: [u8; 32]) -> [u8; 116] {
    let mut output = [0u8; 116];
    output[0..32].copy_from_slice(&nonce_count_hash);
    output[32..64].copy_from_slice(&chain_id_hash);
    output[64..84].copy_from_slice(&beneficiary);
    output[84..116].copy_from_slice(&nonce);
    output
}

pub fn get_new_hash(nonce_count_hash: [u8; 32], chain_id_hash: [u8; 32], beneficiary: [u8; 20], nonce: [u8; 32]) -> [u8; 32] {
    return keccak256(
        keccak256(
            pack_byte_arrays(nonce_count_hash, chain_id_hash, beneficiary, nonce)
        )
    );   
}


pub fn hashmaxxing_multithread(nonce_count_hash: [u8; 32], chain_id_hash: [u8; 32], beneficiary: [u8; 20], targ_hash: Arc<RwLock<[u8; 32]>>, nthreads: usize) -> [u8; 32] {
    
    println!("{}", format!("[{}] Hashmaxxing using {} threads...", localnow(),  nthreads));
    
    let is_nonce_found = Arc::new(RwLock::new(false));
    let found_nonce    = Arc::new(Mutex::new([0u8; 32]));
    
    let mut threads = vec![];

    for i in 0..nthreads {
        let is_nonce_found_clone = is_nonce_found.clone();
        let found_nonce_clone = found_nonce.clone();

        //let prev_hash_clone = prev_hash.clone();
        let targ_hash_clone = targ_hash.clone();

        threads.push(thread::spawn(move || {
            let mut nonce = [0u8; 32];
            let mut rng = thread_rng();
            
            while !*is_nonce_found_clone.read().unwrap() {
                thread_rng().fill_bytes(&mut nonce);
                let new_hash = get_new_hash(nonce_count_hash, chain_id_hash, beneficiary, nonce);

                if H256(new_hash) > H256(*targ_hash_clone.read().unwrap()) {
                    *is_nonce_found_clone.write().unwrap() = true;
                    *found_nonce_clone.lock().unwrap() = nonce;
                    break;
                }
            }
        }));
    }

    for t in threads {
        t.join().unwrap();
    }

    return *found_nonce.lock().unwrap();
}

pub fn hashmaxxing_single_thread(nonce_count_hash: [u8; 32], chain_id_hash: [u8; 32], beneficiary: [u8; 20], targ_hash: [u8; 32]) -> ([u8; 32], u64) {
    let mut nonce = [0u8; 32];
    let targ_hash_h256 = H256(targ_hash);
    let mut i: u64 = 0;
    loop {
        thread_rng().fill_bytes(&mut nonce);
        let new_hash = get_new_hash(nonce_count_hash, chain_id_hash, beneficiary, nonce);

        if H256(new_hash) > targ_hash_h256 {
            break;
        }

        i = i+1;
    }
    (nonce, i)
}
