use crate::{
    cc_snark::data_structure::{Proof, VerifyingKey},
    encryption::{cc_enc::CCEnc, encryption::ElGamal},
    linker::{Linker, snark::LinkSnark},
};
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, Read};
use core::ops::Neg;
use num_bigint::BigInt;
use std::ffi::{CStr, c_char};
use std::fs;
use std::fs::File;

pub mod mimc7;

use crate::{
    CC_PRF_FILE, CC_VK_FILE, CM_FILE, LINK_PRF_FILE, LINK_VK_FILE, TRADE_CC_PRF_FILE,
    TRADE_CC_VK_FILE, TRADE_LINK_PRF_FILE, TRADE_LINK_VK_FILE,
};

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

pub fn cc_proof_from_file<E: Pairing>(proof_file_path: &str, mode: bool) -> String {
    let cc_prf_file = match mode {
        false => CC_PRF_FILE.as_str(),
        true => TRADE_CC_PRF_FILE.as_str(),
    };
    let raw_proof = get_file_as_byte_vec(&format!("{proof_file_path}{cc_prf_file}"));
    let proof = Proof::<E>::deserialize_compressed(raw_proof.as_slice()).unwrap();

    cc_proof_to_string::<E>(proof)
}

pub fn cc_vk_from_file<E: Pairing>(vk_file_path: &str, mode: bool) -> String {
    let cc_vk_file = match mode {
        false => CC_VK_FILE.as_str(),
        true => TRADE_CC_VK_FILE.as_str(),
    };
    let raw_vk = get_file_as_byte_vec(&format!("{vk_file_path}{cc_vk_file}"));
    let vk = VerifyingKey::<E>::deserialize_compressed(raw_vk.as_slice()).unwrap();

    cc_vk_to_string::<E>(vk)
}

pub fn link_proof_from_file<E: Pairing>(proof_file_path: &str, mode: bool) -> String {
    let link_prf_file = match mode {
        false => LINK_PRF_FILE.as_str(),
        true => TRADE_LINK_PRF_FILE.as_str(),
    };
    let raw_proof = get_file_as_byte_vec(&format!("{proof_file_path}{link_prf_file}"));
    let proof =
        <LinkSnark<E> as Linker<E>>::Proof::deserialize_compressed(raw_proof.as_slice()).unwrap();

    link_proof_to_string::<E>(proof)
}

pub fn link_vk_from_file<E: Pairing>(vk_file_path: &str, mode: bool) -> String {
    let link_vk_file = match mode {
        false => LINK_VK_FILE.as_str(),
        true => TRADE_LINK_VK_FILE.as_str(),
    };
    let raw_vk = get_file_as_byte_vec(&format!("{vk_file_path}{link_vk_file}"));
    let vk = <LinkSnark<E> as Linker<E>>::VK::deserialize_compressed(raw_vk.as_slice()).unwrap();

    link_vk_to_string::<E>(vk)
}

pub fn cm_from_file<E: Pairing>(cm_file_path: &str) -> String {
    let cm_file = CM_FILE.as_str();
    let raw_cm = get_file_as_byte_vec(&format!("{cm_file_path}{cm_file}"));
    let cm = E::G1Affine::deserialize_compressed(raw_cm.as_slice()).unwrap();

    cm_to_string::<E>(cm)
}

pub fn cc_proof_to_string<E: Pairing>(proof: Proof<E>) -> String {
    serde_json::json!({
        "a": format!("{:#?}", proof.a),
        "b": format!("{:#?}", proof.b),
        "c": format!("{:#?}", proof.c),
        "cm": format!("{:#?}", proof.cm),
        "open": format!("{:#?}", proof.open),
    })
    .to_string()
}

pub fn cc_vk_to_string<E: Pairing>(vk: VerifyingKey<E>) -> String {
    serde_json::json!({
        "alpha" : format!("{:#?}", vk.alpha_g1),
        "beta" : format!("{:#?}", (vk.beta_g2.into_group().neg()).into_affine()),
        "delta" : format!("{:#?}", (vk.delta_g2.into_group().neg()).into_affine()),
        "gamma" : format!("{:#?}", (vk.gamma_g2.into_group().neg()).into_affine()),
        "abc" : format!("{:#?}", vk.gamma_abc_g1),
        "eta_gamma_inv": format!("{:#?}", vk.eta_gamma_inv_g1),
        "eta_delta_inv": format!("{:#?}", vk.eta_delta_inv_g1),
    })
    .to_string()
}

pub fn link_proof_to_string<E: Pairing>(proof: <LinkSnark<E> as Linker<E>>::Proof) -> String {
    serde_json::json!({
        "proof": format!("{:#?}", proof),
    })
    .to_string()
}

pub fn link_vk_to_string<E: Pairing>(vk: <LinkSnark<E> as Linker<E>>::VK) -> String {
    serde_json::json!({
        "c": format!("{:#?}", vk.c),
        "a": format!("{:#?}", vk.a),
    })
    .to_string()
}

pub fn cm_to_string<E: Pairing>(cm: E::G1Affine) -> String {
    serde_json::json!({
        "cm": format!("{:#?}", cm),
    })
    .to_string()
}

pub fn dec_msg_to_string<E: Pairing>(dec_msg: <ElGamal<E> as CCEnc<E>>::Plaintext) -> String {
    let mut dec_msg_bigint = Vec::new();

    for m_i in dec_msg.msg {
        dec_msg_bigint.push(fr_to_bigint(m_i));
    }
    println!("[Converted] {:#?}", dec_msg_bigint);

    serde_json::json!({
        "msg": format!("{:#?}", dec_msg_bigint),
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

pub fn fr_to_bigint<F: PrimeField>(x: F) -> BigInt {
    let x_bytes = x.into_bigint().to_bytes_be();

    BigInt::from_bytes_be(num_bigint::Sign::Plus, &x_bytes)
}
