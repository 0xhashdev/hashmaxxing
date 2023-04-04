mod helpers;
use helpers::*;

mod web3test;
use web3test::*;

mod hashmaxxing;
use hashmaxxing::*;

use num_cpus;

use json;

use std::env;
use std::io::{self, BufRead, prelude::*};
use std::fs;
// use std::mem;
use std::process;
use std::path::{PathBuf, Path};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Instant, Duration};

use colored::*;

use ndarray::Array;

use rand::prelude::*;
use rand::{Rng, thread_rng};

// use web3_hash_utils::keccak256;

use rpassword::prompt_password;
use clap::{Arg, Command, ArgAction};

use eth_keystore::{encrypt_key, decrypt_key};

use ethers::{
    prelude::*,
    abi::Abi,
    contract::Contract,
    providers::Provider,
    utils::{parse_ether, parse_units, format_units}
};

use std::any::type_name;
fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

use serde_json;

fn bytes_to_hex_string(bytes: &[u8]) -> String {
    let hex_chars: Vec<String> = bytes.iter().map(|byte| format!("{:02X}", byte)).collect();
    format!("0x{}", hex_chars.join(""))
}

fn create_bip39_key () {
    let mne = ethers::signers::coins_bip39::mnemonic::Mnemonic::<ethers::signers::coins_bip39::English>::new(&mut thread_rng());
    println!("mne: {:#?}", mne.to_phrase().unwrap());
    println!("mne key: {:#?}", mne.master_key(None).unwrap());
}

fn split_path(full_path: &str) -> (&str, &str) {
    let mut split_index = full_path.len();

    // Find the last occurrence of '/' or '\'
    for (i, c) in full_path.char_indices().rev() {
        if c == '/' || c == '\\' {
            split_index = i + 1;
            break;
        }
    }

    // Split the string at the last occurrence of '/' or '\'
    let (path, filename) = full_path.split_at(split_index);

    // Return the directory path and the filename as separate strings
    (path, &filename[1..])
}

const license : &str = "Copyright (c) 2022-2023 0xhashdev (0xhashdev@gmx.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.";

#[tokio::main]
async fn main() {

    let __version__ = env!("CARGO_PKG_VERSION");
    let cmd = Command::new("Hashmaxxing")
        .author("0xhashdev")
        .version("0.1.0")
        .about("I am an autist.")
        .subcommand(Command::new("start")
            .about("Start mining")
            .arg(
                Arg::new("nthreads").short('j').long("threads").help("Use `j` threads for hashmaxxing. By default the program is using all available threads.")
            )
            .arg(
                Arg::new("target_hash_refresh_rate").short('t').long("target-hash-refresh-rate").help("Scan for target hash change every `t` seconds. Default is 10 seconds")
            )
            .arg(
                Arg::new("dry_run").short('d').long("dry-run").action(ArgAction::SetTrue).help("Do not send transaction and exit after the first nonce is found.")
            )
            .arg(
                Arg::new("yes").short('y').long("yes").action(ArgAction::SetTrue).help("Aggree to everything and proceed.")
            )
            .arg(
                Arg::new("network").short('n').long("network").help("Network to use. Defaults to `ethereum`.")
            )
            .arg(
                Arg::new("beneficiary").short('b').long("beneficiary").help("Tokens will be sent to this address. It is recommended to use a different address than the address you use for paying gas fees.")
            )
            .arg(
                Arg::new("gasless").short('g').long("gasless").action(ArgAction::SetTrue).help("Gasless usage. Not supported currently")
            )
            .arg(
                Arg::new("privkey_path").short('k').long("privkey-path").help("Path to private key. Should be something like /path/to/key.json")
            )
            .arg(
                Arg::new("password").short('p').long("password")
                .help(format!("{} {}", "Password for the private key.", format!("WARNING: Never share your password. Only use this if you want to bypass entering the password manually.").red().bold() ) )
            )
        )
        .subcommand(Command::new("benchmark")
            .about("Benchmark hashmaxxing")
            .arg(
                Arg::new("nthreads").short('j').long("threads").help("Use `j` threads for hashmaxxing")
            )
            .arg(
                Arg::new("nsamples").short('s').long("samples").help("Use `s` samples")
            )
            .arg(
                Arg::new("hashrate").long("hashrate").action(ArgAction::SetTrue).help("Benchmark hashrate only")
            )
        )
        .subcommand(Command::new("config")
            .about("Configure settings")
            .subcommand(Command::new("get")
                .arg(
                    Arg::new("key")
                )
            ).about("Get value of key")
            .subcommand(Command::new("set")
                .arg(
                    Arg::new("key")
                )
                .arg(
                    Arg::new("value")
                )
            ).about("Set value of key")
            .subcommand(Command::new("dump")
            )
            .about("Print all config.")
        )
        .subcommand(Command::new("generate-address")
            .about("Generates a new address")
            .arg(
                Arg::new("output").short('o').long("output").required(true).help("Save encrypted private key to this path.")
            )
        )
        .after_help(
            "Longer explanation to appear after the options when \
            displaying the help information from --help or -h"
        );

    println!("{}", "\n=======================================================".bright_blue().bold());
    println!("{}             {} {}             {}", "||".bright_blue().bold(), "Hashmaxxing version".bright_blue().bold(), __version__.bright_blue().bold(), "||".bright_blue().bold());
    println!("{}", "=======================================================".bright_blue().bold());
    println!("{}", license);

    // Parse command line arguments.
    let matches = cmd.get_matches();

    let conf_path_env_var = "HASHMAXXING_CONFIG_PATH"; // this environment variable should point to a directory which contains chains.json and contracts.json
    let mut config_path = PathBuf::new();
    match env::var_os(conf_path_env_var) {
        Some(val) => {
            config_path.push(val);
        }
        None => {
            println!("[{}] {}",  localnow(), format!("WARNING: {} is not defined in the environment.", conf_path_env_var).yellow());
            config_path.push(&env::current_dir().unwrap());
            config_path.push("config")
        }
    }

    if let Some(config_matches) = matches.subcommand_matches("config") {

        
        println!("[{}] Loading config from {:?}...", localnow(), config_path.join("config.json"));
        match fs::read_to_string(&config_path.join("config.json")) {
            Ok(jsonstring) => {
                match json::parse( &jsonstring ) {
                    Ok(jsonvalue) => {
                        let mut config = jsonvalue;

                        if let Some(dump_matches) = config_matches.subcommand_matches("get") {
                            println!("{}", config.pretty(4).as_str());
                        }

                        if let Some(get_matches) = config_matches.subcommand_matches("get") {
                            if let Some(key) = get_matches.get_one::<String>("key") {
                                if config.has_key(key) {
                                    println!("Value of {} is {:?}", key, config[key]);
                                } else {
                                    println!("Invalid key {}", key);
                                }
                            }
                        }
                
                        if let Some(set_matches) = config_matches.subcommand_matches("set") {
                            if let Some(key) = set_matches.get_one::<String>("key") {
                                if let Some(value) = set_matches.get_one::<String>("value") {
                                    if config.has_key(key) {
                                        println!("Setting value of {} to {}", key, value);
                                        config[key] = json::JsonValue::from(value.as_str());

                                        match fs::File::create(&config_path.join("config.json")) {
                                            Ok(mut file) => {
                                                file.write_all(config.pretty(4).as_bytes());
                                            }
                                            Err(error) => {
                                                eprintln!("Error saving config file: {}", error);
                                                process::exit(0x02);
                                            }
                                        }
                                    } else {
                                        println!("Invalid key {}", key);
                                    }
                                }
                            }
                        }

                    }
                    Err(error) => {
                        eprintln!("Error parsing config: {}", error);
                        process::exit(0x02);
                    } 
                }
                
            }
            Err(error) => {
                eprintln!("Error reading config file: {}", error);
                process::exit(0x02);
            } 
        }
    
        
    }

    if let Some(matches) = matches.subcommand_matches("start") {

        // Read config file 
        println!("[{}] Loading config from {:?}...", localnow(), config_path.join("config.json"));
        
        let mut config = json::parse("{}").unwrap();
        match fs::read_to_string(&config_path.join("config.json")) {
            Ok(jsonstring) => {
                match json::parse( &jsonstring ) {
                    Ok(jsonvalue) => {
                        config = jsonvalue;
                    }
                    Err(error) => {
                        eprintln!("{}", format!("Error parsing config: {}", error).red().bold());
                        process::exit(0x02);
                    } 
                }
                
            }
            Err(error) => {
                eprintln!("{}", format!("Error reading config file: {}", error).red().bold());
                process::exit(0x02);
            } 
        }

        // Read config file 
        println!("[{}] Loading chains from {:?}...", localnow(), config_path.join("chains.json"));

        let mut chains = json::parse("{}").unwrap();
        match fs::read_to_string(&config_path.join("chains.json")) {
            Ok(jsonstring) => {
                match json::parse( &jsonstring ) {
                    Ok(jsonvalue) => {
                        chains = jsonvalue;
                    }
                    Err(error) => {
                        eprintln!("{}", format!("Error parsing chains: {}", error).red().bold());
                        process::exit(0x02);
                    } 
                }
                
            }
            Err(error) => {
                eprintln!("{}", format!("Error reading chains.json: {}", error).red().bold());
                process::exit(0x02);
            } 
        }

        // Read config file 
        println!("[{}] Loading contracts from {:?}...", localnow(), config_path.join("contracts.json"));

        let mut contracts = json::parse("{}").unwrap();
        match fs::read_to_string(&config_path.join("contracts.json")) {
            Ok(jsonstring) => {
                match json::parse( &jsonstring ) {
                    Ok(jsonvalue) => {
                        contracts = jsonvalue;
                    }
                    Err(error) => {
                        eprintln!("{}", format!("Error parsing contracts: {}", error).red().bold());
                        process::exit(0x02);
                    } 
                }
                
            }
            Err(error) => {
                eprintln!("{}", format!("Error reading chains.json: {}", error).red().bold());
                process::exit(0x02);
            } 
        }

        // Load private key 
        let mut privkey: [u8; 32];
        let mut password: String;

        let mut privkey_path = PathBuf::new();
        if let Some(kpathstr) = matches.get_one::<String>("privkey_path") {
            privkey_path.push(kpathstr);
        
        } else {
            
            // Try to load from HASHMAXXING_ACCOUNT_PATH
            let acc_path_env_var = "HASHMAXXING_ACCOUNTS_PATH"; // this environment variable should point to a directory which contains accounts
            let mut accounts_path = PathBuf::new();
            match env::var_os(acc_path_env_var) {
                Some(val) => {
                    privkey_path.push(val);
                    privkey_path.push("default_account.json");
                }
                None => {
                    println!("[{}] {}",  localnow(), format!("WARNING: {} is not defined in the environment.", acc_path_env_var).yellow());
                }
            }
        }
        
        // Check if private key exists at given path
        if !privkey_path.exists() || !privkey_path.is_file() {
            eprintln!("{}", format!("Can't load private key from file at {}. The file does not exist.", privkey_path.to_str().unwrap()).red().bold());
            process::exit(0x01);
        } else {
            if let Some(pass) = matches.get_one::<String>("password") {
                password = pass.to_string();
            } else {
                password = prompt_password(format!("Enter password for {}:", privkey_path.to_str().unwrap())).unwrap();
            }
        }
           
        privkey = get_privkey_from_path(&privkey_path, password.as_str());
       

        let mut selected_chain_name = "ethereum";
        if let Some(network) = matches.get_one::<String>("network") {
            selected_chain_name = network;
        } else {
            println!("{}", format!("INFO: No network specified. Defaulting to `ethereum`.").yellow().bold());

        }
       
        let mut selected_chain_rpc = "";
        match chains[selected_chain_name]["rpcs"][0].as_str() {
            Some (rpc) => {
                selected_chain_rpc = rpc;
            }
            None => {
                println!("{}", format!("ERROR Cannot read rpc url for chain {}.", selected_chain_name).red().bold());
            }
        };
        
        let mut selected_chain_id: u64 = 0;
        match chains[selected_chain_name]["chainID"].as_u64() {
            Some (chain_id) => {
                selected_chain_id = chain_id;
            }
            None => {
                println!("{}", format!("ERROR Cannot read chain id chain {}.", selected_chain_name).red().bold());
            }
        };
        
        let mut selected_chain_explorer = "";
        match chains[selected_chain_name]["explorers"][0].as_str() {
            Some (explorer_url) => {
                selected_chain_explorer = explorer_url;
            }
            None => {
                println!("{}", format!("ERROR Cannot read explorer url for chain {}.", selected_chain_name).red().bold());
            }
        };


        let selected_beneficiary: String;
        if let Some(beneficiary) = matches.get_one::<String>("beneficiary") {
            selected_beneficiary = beneficiary.to_string();
        } else {
            eprintln!("{}", format!("No beneficiary. Set one using --beneficiary=<your address>").red().bold());
            process::exit(0x10);
        }

        let provider  = get_provider( &selected_chain_rpc );
        let wallet = create_wallet(privkey,  selected_chain_id);

        let client = instantiate_client(
            privkey,
            selected_chain_id, 
            &selected_chain_rpc
        );

        let mut ethgasbalance: String = "0.0".to_string();
        match client.get_balance(wallet.address(), None).await {
            Ok(balance) => { 
                ethgasbalance = format_units(balance, "ether").unwrap();
            }
            Err(e)=> { 
                println!("{}", format!("ERROR fetching gas balance: {}", e).red().bold());
                process::exit(0x03);
            }
        }

        let infos = format!("INFO: Your wallet address: {:?}, Gas balance: {} ETH.", wallet.address(), ethgasbalance);
        println!("{} {}", infos.yellow().bold(), "This ETH is only used to pay gas fees when sendig nonces to the contract".magenta());
        
        let infos = format!("INFO: beneficiary address: {}.", selected_beneficiary);
        println!("{} {}", infos.yellow().bold(), "This address will receive tokens.".magenta());

        
        if matches.get_flag("yes") {
            println!("Continuing...");
        } else {
            println!("{}", "Continue?".magenta().bold());
            let positive_inputs = ["y", "Y", "yes", "Yes", "YES"];
            let input = io::stdin().lock().lines().next().unwrap().unwrap();
            if !positive_inputs.contains(&input.as_str()) {
                println!("Aborted.");
                process::exit(0);
            }
        }

        let mut selected_contract_address = "";
        match contracts[selected_chain_name]["address"].as_str() {
            Some (addr) => {
                selected_contract_address = addr;
            }
            None => {
                println!("{}", format!("ERROR Cannot read contract address for chain {}.", selected_chain_name).red().bold());
            }
        };
        
        let contract = Arc::new(
            instantiate_contract(
                selected_contract_address,
                &contracts[selected_chain_name]["abi"].dump(),
                provider
            )
        );

        println!("{}", format!("INFO: You are interacting with contract {} on chain {}", selected_contract_address , selected_chain_name).yellow().bold());

        // Get nonce count hash from contract
        let mut nonce_count_hash = [0u8; 32];
        match contract.method::<H160, [u8; 32]>(
            "getNonceCountHash", 
            H160(addr2bytes(&selected_beneficiary))
        ) {
            Ok (nonce_count_hash_req) => {
                match nonce_count_hash_req.call().await {
                    Ok (nonce_count_hash_resp) => {
                        nonce_count_hash = nonce_count_hash_resp;
                        println!("{}", format!("[{}] nonce_count_hash: {}", localnow(),  bytes2hex(nonce_count_hash)));
                    }
                    Err (nonce_count_hash_err) => {
                        println!("{}", format!("Error while calling `getNonceCountHash`: {:?}", nonce_count_hash_err).red().bold());
                        process::exit(0x03);
                    } 
                }
            }
            Err (nonce_count_hash_err) => {
                println!("{}", format!("Error while calling `getNonceCountHash`: {:?}", nonce_count_hash_err).red().bold());
                process::exit(0x03);
            } 
        }

        // Get chain id hash from contract
        let mut chainid_hash = [0u8; 32];
        match contract.method::<_, [u8; 32]>(
            "getChainIdHash",
            ()
        ) {
            Ok (chainid_hash_req) => {
                match chainid_hash_req.call().await {
                    Ok (chainid_hash_resp) => {
                        chainid_hash = chainid_hash_resp;
                        println!("{}", format!("[{}] chainid_hash: {}", localnow(),  bytes2hex(chainid_hash)));
                    }
                    Err (chainid_hash_err) => {
                        println!("{}", format!("Error while calling `getChainIdHash`: {:?}", chainid_hash_err).red().bold());
                        process::exit(0x03);
                    } 
                }
            }
            Err (chainid_hash_err) => {
                println!("{}", format!("Error while calling `getChainIdHash`: {:?}", chainid_hash_err).red().bold());
                process::exit(0x03);
            } 
        }
        

        let shared_targ_hash = Arc::new(RwLock::new([0u8; 32]));
        match contract.method::<_, [u8; 32]>(
            "getTargetHash", 
            ()
        ) {
            Ok (target_hash_req) => {
                match target_hash_req.call().await {
                    Ok (target_hash_resp) => {
                        *shared_targ_hash.write().unwrap() = target_hash_resp;
                        println!("{}", format!("[{}] target_hash: {}", localnow(),  bytes2hex(*shared_targ_hash.clone().read().unwrap())));
                    }
                    Err (target_hash_err) => {
                        println!("{}", format!("Error while calling `getChainIdHash`: {:?}", target_hash_err).red().bold());
                        process::exit(0x03);
                    } 
                }
            }
            Err (target_hash_err) => {
                println!("{}", format!("Error while calling `getChainIdHash`: {:?}", target_hash_err).red().bold());
                process::exit(0x03);
            } 
        }

        let mut target_hash_refresh_rate = 10.0;
        if let Some(t) = matches.get_one::<String>("target_hash_refresh_rate") {
            target_hash_refresh_rate =  t.parse::<f32>().unwrap();
            println!("Value for -t: {}", target_hash_refresh_rate);
        }

        // Create a new thread
        // No need for handle, thread runs endlessly until application is closed.
        let thread_contract = contract.clone();
        let thread_shared_targ_hash = shared_targ_hash.clone();
        thread::spawn(move || {
            // Infinite loop to update shared_targ_hash
            loop {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                   
                    match (thread_contract.method::<_, [u8; 32]>(
                        "getTargetHash", 
                        ()
                    ) ).unwrap().call().await {
                        Ok(new_target_hash) => {

                            if new_target_hash != *thread_shared_targ_hash.read().unwrap() {
                                println!("{}", format!("[{}] Received new target hash: {:?}", localnow(), bytes2hex(new_target_hash)).bright_blue());
                                *thread_shared_targ_hash.write().unwrap() = new_target_hash;
                            }

                        }
                        Err(error)=> {
                            println!("{}", format!("ERROR fetching new target_hash: {}", error).red().bold());
                            process::exit(0x03);
                        }
                    }

                    // Wait 
                    thread::sleep(Duration::from_secs_f32(target_hash_refresh_rate));
                });
            }
        });

        let mut nthreads: usize = 0;
        if let Some(n) = matches.get_one::<String>("nthreads") {
            nthreads = n.parse::<usize>().unwrap()
        } else {
            nthreads = num_cpus::get();
        }

        // Main loop for searching for the nonce
        loop {

            let new_nonce = hashmaxxing_multithread(
                nonce_count_hash,
                chainid_hash, 
                addr2bytes( &selected_beneficiary ), 
                shared_targ_hash.clone(), 
                4
            );
    
            println!("{}", 
                format!("[{}] 🍺 Nonce found!\nnonce: {:?}\ntarget_hash: {:?}\nnew_hash: {:?}", 
                    localnow(), 
                    bytes2hex(new_nonce),
                    bytes2hex( *shared_targ_hash.clone().read().unwrap() ),
                    bytes2hex(
                        get_new_hash(nonce_count_hash, chainid_hash, addr2bytes( &selected_beneficiary ), new_nonce)
                    )
                ).magenta().bold()
            );

            println!("{}", format!("NOTE: Hashgold currently has low liquidity. Kindly, use some of your tokens to provide DEX liquidity.").bright_red().bold());
    
            if !matches.get_flag("dry_run") {

                let call = contract.method::<(H160, H256), H256 >("hashmaxx", (H160(addr2bytes(&selected_beneficiary)), H256(new_nonce))).unwrap();

                // TODO: Handle gas fee changes! Currently the program fails if maxFeePerGas < baseFee. need to fetch gas price and adjust tx accordingly
                if chains[selected_chain_name]["isEIP1559"].as_bool().unwrap() {

                    match client.send_transaction(call.tx.clone(), None).await {
                        Ok(resp) => {
                            
                            println!("{}", format!("[{}] Transaction (EIP1559) submitted. Waiting for confirmation...", localnow()));

                            match resp.await {
                                Ok (txok) => {
                                    match txok {
                                        Some(confirmed_tx) => {
                                            println!("{}", format!("[{}] Tx confirmed. Check {}tx/{:?}", localnow(),  selected_chain_explorer,  confirmed_tx.transaction_hash ));

                                            match contract.method::<H160, [u8; 32]>(
                                                "getNonceCountHash", 
                                                H160(addr2bytes(&selected_beneficiary))
                                            ) {
                                                Ok (nonce_count_hash_req) => {
                                                    match nonce_count_hash_req.call().await {
                                                        Ok (nonce_count_hash_resp) => {
                                                            nonce_count_hash = nonce_count_hash_resp;
                                                            println!("{}", format!("[{}] New nonce_count_hash: {}", localnow(),  bytes2hex(nonce_count_hash)));
                                                        }
                                                        Err (nonce_count_hash_err) => {
                                                            println!("{}", format!("Error while calling `getNonceCountHash`: {:?}", nonce_count_hash_err).red().bold());
                                                            process::exit(0x03);
                                                        } 
                                                    }
                                                }
                                                Err (nonce_count_hash_err) => {
                                                    println!("{}", format!("Error while calling `getNonceCountHash`: {:?}", nonce_count_hash_err).red().bold());
                                                    process::exit(0x03);
                                                } 
                                            }
                                        }
                                        None => {
                                            println!("{}", format!("Error while unwrapping `confirmed_tx`: {}\nTried to send the following tx:\n {:?}", "txok is None", call.tx.clone()).red().bold());
                                            process::exit(0x03);
                                        }
                                    }
                                }
                                Err (e) => {
                                    println!("{}", format!("Error while unwrapping `txok`: {}\nTried to send the following tx:\n {:?}", e, call.tx.clone()).red().bold());
                                    process::exit(0x03);
                                }
                            }
                        
                        }
                        Err(e) => {
                            println!("{}", format!("Error while `resp.await`: {}\nTried to send the following tx:\n {:?}", e, call.tx).red().bold());
                            process::exit(0x03);
                        }
                    }
                } else {
    
                    let legacytx = TransactionRequest {
                        from: call.tx.from().copied(),
                        to: call.tx.to().cloned(),
                        gas: call.tx.gas().copied(),
                        gas_price: call.tx.gas_price(),
                        value: call.tx.value().copied(),
                        data: call.tx.data().cloned(),
                        nonce: call.tx.nonce().copied(),
                        chain_id: call.tx.chain_id()
                    };
                
                    match client.send_transaction(legacytx.clone(), None).await {
                        Ok(resp) => {

                            println!("{}", format!("[{}] Transaction (legacy) submitted. Waiting for confirmation...", localnow()));

                            match resp.await {
                                Ok (txok) => {
                                    match txok {
                                        Some(confirmed_tx) => {
                                            println!("{}", format!("[{}] Tx confirmed. Check {}tx/{:?}", localnow(),  selected_chain_explorer,  confirmed_tx.transaction_hash ));

                                            match contract.method::<H160, [u8; 32]>(
                                                "getNonceCountHash", 
                                                H160(addr2bytes(&selected_beneficiary))
                                            ) {
                                                Ok (nonce_count_hash_req) => {
                                                    match nonce_count_hash_req.call().await {
                                                        Ok (nonce_count_hash_resp) => {
                                                            nonce_count_hash = nonce_count_hash_resp;
                                                            println!("{}", format!("[{}] New nonce_count_hash: {}", localnow(),  bytes2hex(nonce_count_hash)));
                                                        }
                                                        Err (nonce_count_hash_err) => {
                                                            println!("{}", format!("Error while calling `getNonceCountHash`: {:?}", nonce_count_hash_err).red().bold());
                                                            process::exit(0x03);
                                                        } 
                                                    }
                                                }
                                                Err (nonce_count_hash_err) => {
                                                    println!("{}", format!("Error while calling `getNonceCountHash`: {:?}", nonce_count_hash_err).red().bold());
                                                    process::exit(0x03);
                                                } 
                                            }
                                            
                                        }
                                        None => {
                                            println!("{}", format!("Error while unwrapping `confirmed_tx`: {}\nTried to send the following tx:\n {:?}", "txok is None", call.tx.clone()).red().bold());
                                            process::exit(0x03);
                                        }
                                    }
                                }
                                Err (e) => {
                                    println!("{}", format!("Error while unwrapping `txok`: {}\nTried to send the following tx:\n {:?}", e, call.tx.clone()).red().bold());
                                    process::exit(0x03);
                                }
                            }
                           
                        }
                        Err(e) => {
                            println!("{}", format!("Error while `resp.await`: {}\nTried to send the following tx:\n {:?}", e, call.tx).red().bold());
                            process::exit(0x03);
                        }
                    }
                }      
            }
        }
        
    }

    if let Some(matches) = matches.subcommand_matches("benchmark") {
        
        if (!matches.get_flag("hashrate") ) {

            let mut nthreads: usize = 0;
            if let Some(n) = matches.get_one::<String>("nthreads") {
                nthreads = n.parse::<usize>().unwrap()
            } else {
                nthreads = 1;
            }

            let mut nsamples: usize = 0;
            if let Some(n) = matches.get_one::<String>("nsamples") {
                nsamples = n.parse::<usize>().unwrap()
            } else {
                nsamples = 10;
            }

            println!("Running full hashmaxxing benchmark with {} threads and {} samples", nthreads, nsamples);
            
            let expinc: u8 = 8;
            let niter: u64 = 256/(expinc as u64);
            let mut pos: usize = 0;

            let mut target_bytes: [u8; 32] = hex2bytes("0x000000000000000000000000000000000000000000000000000000000b00b1e5");
            
            println!("target_hash|mean_k|std_k|mean_t_millis|std_t_millis");
                
            for i in 0..(32*niter) { 
                let mut ks: Vec<f64> = Vec::new();
                let mut ts: Vec<f64> = Vec::new();
                

                for j in 0..nsamples {
                    let now = Instant::now();
                    let (_, k) = hashmaxxing_single_thread(
                        hex2bytes("0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"),
                        hex2bytes("0x695c3760369950e28bbb1c1005c6b4197eb20e65a06e6f8ce8072c2c7c2744f0"), 
                        addr2bytes("0x4b509b3e029e3674F32527552096683eFfe91A33"), 
                        target_bytes
                    );
                    ks.push(k as f64);
                    ts.push(now.elapsed().as_millis() as f64);
                }

                let mean_t = Array::from_vec(ts.clone()).mean();
                let std_t =  Array::from_vec(ts.clone()).std(1.0);

                let mean_k = Array::from_vec(ks.clone()).mean();
                let std_k =  Array::from_vec(ks.clone()).std(1.0);

                println!("{:?}|{:?}|{:?}|{:?}|{:?}", bytes2hex(target_bytes), mean_k.unwrap(), std_k, mean_t.unwrap(), std_t);
                
                if i % niter == 0 && i>0 {
                    pos = pos+1;
                } 
                
                target_bytes[pos] = target_bytes[pos].saturating_add(expinc);
            }
        } else {
            println!("Benchmarking hashrate");

            let mut nonce = [0u8; 32];

            let prev_hash = hex2bytes("0x2aee8f79bc7ad67c30c495430b6e5b6de8fed05601a8c01f7ded417211fd62e1");
            let chain_id_hash = hex2bytes("0x695c3760369950e28bbb1c1005c6b4197eb20e65a06e6f8ce8072c2c7c2744f0");
            let beneficiary = addr2bytes("0x4b509b3e029e3674F32527552096683eFfe91A33");
           
            let mut i: u64 = 0;
            
            let mut ts: Vec<f64> = Vec::new();
            for j in 0..10 {
                let now = Instant::now();
                for i in 0..100000 {
                    rand::thread_rng().fill_bytes(&mut nonce);
                    let packed_bytes = pack_byte_arrays(prev_hash, chain_id_hash, beneficiary, nonce);
                }
                println!("Performed 100k hashes in {:?}.", now.elapsed());
                ts.push(now.elapsed().as_micros() as f64);
            }
            let mean_t = Array::from_vec(ts.clone()).mean();
            println!("Average hashrate is {:?} H/s", ( 100000.0 * (1000000.0/mean_t.unwrap()) ) as u64 );
        }
    }

    if let Some(matches) = matches.subcommand_matches("generate-address") {

        if let output_path = matches.get_one::<String>("output") {
            
            let mut rng = rand::thread_rng();
            let argpath = Path::new(output_path.unwrap());

            
            let mut full = PathBuf::new();
            let mut dir = PathBuf::new();
            let mut filename = PathBuf::new();

            if let Some(parent) = argpath.parent() {
                full.push(parent);
                dir.push(parent);
            }

            if let Some(fname) = argpath.file_name() {
                full.push(fname);
                full.set_extension("json");
                filename.push(fname);
                filename.set_extension("json");
            } else {
                full.push("key.json");
                filename.push("key.json");
            }

            // Do not overwrite existing keys
            if full.exists() {
                eprintln!("Error: File {:?} already exists", full);
                process::exit(0x03);
            }

            println!("Creating new address and saving key to {:?}...", full);

            let mut password: String;
            loop {
                let password1 = prompt_password("Password:").unwrap();
                let password2 = prompt_password("Confirm password:").unwrap();

                if password1 == password2 {
                    password = password1;
                    break;
                } else {
                    println!("Passwords don't match");
                }
            }

            match fs::create_dir_all(&dir) {
                Ok (()) => {
                    let mut privkey = [0u8; 32];
                    rand::thread_rng().fill_bytes(&mut privkey);
                    match encrypt_key(&dir, &mut rng, &privkey, password, Some(filename.to_str().unwrap())) {
                        Ok(s) => {
                            let address = bytes2hex(privkey)[2..].parse::<LocalWallet>().unwrap().address();
                            println!("Created new wallet with address {:?}", address);
                        }
                        Err(error) => {
                            eprintln!("Error creating wallet: {}", error);
                            process::exit(0x02);
                        } 
                    }
                }
                Err(error) => {
                    eprintln!("Error creating directory: {}", error);
                    process::exit(0x03);
                } 
            }
            
        }
    }
   
}


// use std::thread;
// use std::time::Duration;

// fn main() {
//     let mut counter = 0;
//     let handle = thread::spawn(move || {
//         loop {
//             counter += 1;
//             println!("Counter: {}", counter);
//             thread::sleep(Duration::from_secs(10));
//         }
//     });
//     handle.join().unwrap();
// }

// =======================================================
// ||             Hashmaxxing version 0.0.1             ||
// =======================================================
