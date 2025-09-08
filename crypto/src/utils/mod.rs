use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, Read};
use core::ops::Neg;
use std::ffi::{CStr, c_char};
use std::fs;
use std::fs::File;

use crate::{PRF_FILE, VK_FILE};

pub fn path_from_c_str(ptr: *const c_char, log_prefix: &str) -> Option<&str> {
    let c_str = unsafe { CStr::from_ptr(ptr) };
    let path_str = c_str.to_str().expect("Failed to convert CStr to str");
    Some(path_str)
}

pub fn get_file_as_byte_vec(filename: &String) -> Vec<u8> {
    let mut f = File::open(&filename).expect("no file found");
    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}

pub fn proof_from_file<E: Pairing>(proof_file_path: &str) -> String {
    let prf_file = PRF_FILE.as_str();
    let raw_proof = get_file_as_byte_vec(&format!("{proof_file_path}{prf_file}"));
    let proof = Proof::<E>::deserialize_compressed(raw_proof.as_slice()).unwrap();

    proof_to_string::<E>(proof)
}

pub fn vk_from_file<E: Pairing>(vk_file_path: &str) -> String {
    let vk_file = VK_FILE.as_str();
    let raw_vk = get_file_as_byte_vec(&format!("{vk_file_path}{vk_file}"));
    let vk = VerifyingKey::<E>::deserialize_compressed(raw_vk.as_slice()).unwrap();

    vk_to_string::<E>(vk)
}

pub fn proof_to_string<E: Pairing>(proof: Proof<E>) -> String {
    serde_json::json!({
        "a": format!("{:#?}", proof.a),
        "b": format!("{:#?}", proof.b),
        "c": format!("{:#?}", proof.c),
    })
    .to_string()
}

pub fn vk_to_string<E: Pairing>(vk: VerifyingKey<E>) -> String {
    serde_json::json!({
        "alpha" : format!("{:#?}", vk.alpha_g1),
        "beta" : format!("{:#?}", (vk.beta_g2.into_group().neg()).into_affine()),
        "delta" : format!("{:#?}", (vk.delta_g2.into_group().neg()).into_affine()),
        "gamma" : format!("{:#?}", (vk.gamma_g2.into_group().neg()).into_affine()),
        "abc" : format!("{:#?}", vk.gamma_abc_g1),
    })
    .to_string()
}

pub fn string_from_ptr(ptr: *const c_char) -> String {
    unsafe {
        let cstr = CStr::from_ptr(ptr);
        let str_slice = cstr.to_str().expect("Invalid UTF-8");
        str_slice.to_string()
    }
}

pub fn parse_prime_fields<E: Pairing>(input_string: &str) -> Vec<E::ScalarField> {
    let delimiter = ',';
    input_string
        .split(delimiter)
        .filter_map(|s| s.parse::<E::ScalarField>().ok())
        .collect()
}
