use std::fmt::Write;
use std::mem;

use ethers::{
    prelude::*,
};

use chrono::offset::*;

pub fn  localnow() -> String {
    return format!("{}", Local::now());
}

pub fn eth2wei(ethval: f64) -> U256 {
    return U256([0,0,0, (ethval as u64)]) * (1_000000_000000_000000 as u64);
}

pub fn wei2eth(weival: U256) -> f64 {
    return (weival.low_u64() as f64) * 0.000000000000000001;
}

pub fn bytes2hex(bytes: [u8; 32]) -> String {
    let mut hex_string = String::with_capacity(66);
    hex_string.push_str("0x");
    for byte in &bytes {
        write!(hex_string, "{:02x}", byte).unwrap();
    }
    hex_string
}

pub fn hex2bytes(hex_string: &str) -> [u8; 32] {
    let mut bytes = [0; 32];
    let hex_string = &hex_string[2..];
    for (i, byte_str) in hex_string.as_bytes().chunks(2).enumerate() {
        let byte = u8::from_str_radix(std::str::from_utf8(byte_str).unwrap(), 16).unwrap();
        bytes[i] = byte;
    }
    bytes
}

pub fn bytes2addr(bytes: [u8; 20]) -> String {
    let mut hex_string = String::with_capacity(42);
    hex_string.push_str("0x");
    for byte in &bytes {
        write!(hex_string, "{:02x}", byte).unwrap();
    }
    hex_string
}

pub fn addr2bytes(hex_string: &str) -> [u8; 20] {
    let mut bytes = [0; 20];
    let hex_string = &hex_string[2..];
    for (i, byte_str) in hex_string.as_bytes().chunks(2).enumerate() {
        let byte = u8::from_str_radix(std::str::from_utf8(byte_str).unwrap(), 16).unwrap();
        bytes[i] = byte;
    }
    bytes
}

// Takes a [u8; 32] variable as input, and returns a [u64; 4] variable. 
// The conversion is done using unsafe Rust code, which allows low-level manipulation of memory.
// The mem::uninitialized function is used to create an uninitialized array of u64 values. 
// This array is then filled with the data from the input array using the ptr::copy_nonoverlapping function, which is part of the std::ptr module.
// The ptr::copy_nonoverlapping function takes two pointers as inputs, and copies data from the first pointer to the second pointer. The 4 argument specifies the number of u64 values to be copied.
// Note that the use of unsafe code can introduce undefined behavior and security vulnerabilities if not used correctly. In this example, the conversion is safe because the input array is guaranteed to have a size of 32, which is a multiple of 8, the size of u64.
pub fn convert_u8_to_u64(array: [u8; 32]) -> [u64; 4] {
    unsafe {
        let mut result: [u64; 4] = mem::uninitialized();
        let src_ptr = array.as_ptr() as *const u64;
        let dst_ptr = result.as_mut_ptr();
        std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, 4);
        result
    }
}

pub fn convert_u64_to_u8(array: [u64; 4]) -> [u8; 32] {
    unsafe {
        let mut result: [u8; 32] = mem::uninitialized();
        let src_ptr = array.as_ptr() as *const u8;
        let dst_ptr = result.as_mut_ptr();
        std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, 32);
        result
    }
}

// pub fn convert_u64_to_u8(input: [u64; 4]) -> [u8; 32] {
//     let mut output = [0u8; 32];
//     for (i, item) in input.iter().enumerate() {
//         let bytes = item.to_be_bytes();
//         let start = i * 8;
//         let end = start + 8;
//         output[start..end].copy_from_slice(&bytes);
//     }
//     output
// }