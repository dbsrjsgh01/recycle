#![allow(
    dead_code,
    unused_imports,
    unused_mut,
    unused_variables,
    unused_macros,
    unused_assignments,
    unreachable_patterns
)]

pub mod circuit;
pub mod utils;

pub use ark_crypto_primitives::*;
pub use ark_ec::*;
pub use ark_ff::*;
pub use ark_poly::*;

use ark_serialize::CanonicalSerialize;
pub use pairing::*;
use rand::SeedableRng;

pub(crate) type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
pub(crate) type BasePrimeField<E> =
    <<<E as Pairing>::G1Affine as CurveGroup>::BaseField as Field>::BasePrimeField;

#[macro_use]
extern crate ark_std;

#[cfg(feature = "r1cs")]
#[macro_use]
extern crate derivative;

use crate::circuit::Circuit;
use ark_bn254::{Bn254 as E, Fr as F};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey, prepare_verifying_key};
pub use ark_std::{marker::PhantomData, test_rng, vec::Vec};
use rand::RngCore;
use std::{
    convert::TryInto,
    ffi::{CString, c_char},
    fs,
    ops::Mul,
    sync::Mutex,
};
use utils::{
    get_file_as_byte_vec, path_from_c_str, proof_from_file, string_from_ptr, vk_from_file,
};

#[macro_use]
extern crate lazy_static;

// 할 일
// 1. Proof, VK -> String이 아닌 각자의 형식
// 2. Input 직접 변환해서 넣기
// 3. 나머지 구현

lazy_static! {
    pub static ref PK_FILE: String = "pk.dat".to_string();
    pub static ref VK_FILE: String = "vk.dat".to_string();
    pub static ref PRF_FILE: String = "proof.dat".to_string();
    static ref PK: Mutex<ProvingKey<E>> = Mutex::new(ProvingKey {
        vk: Default::default(),
        beta_g1: Default::default(),
        delta_g1: Default::default(),
        a_query: Vec::new(),
        b_g1_query: Vec::new(),
        b_g2_query: Vec::new(),
        h_query: Vec::new(),
        l_query: Vec::new(),
    });
    static ref VK: Mutex<VerifyingKey<E>> = Mutex::new(VerifyingKey {
        alpha_g1: Default::default(),
        beta_g2: Default::default(),
        gamma_g2: Default::default(),
        delta_g2: Default::default(),
        gamma_abc_g1: Vec::new(),
    });
    static ref PRF: Mutex<Proof<E>> = Mutex::new(Proof {
        a: Default::default(),
        b: Default::default(),
        c: Default::default(),
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn setup_bn254(param_path: *const c_char, len: usize) -> bool {
    let path = match utils::path_from_c_str(param_path, "[param_path]") {
        Some(p) => p,
        None => return false,
    };

    let circuit = Circuit::<F>::mock(len);

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit, &mut rng).unwrap();

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes).unwrap();
    let pk_file = PK_FILE.as_str();
    fs::write(format!("{path}{pk_file}"), pk_bytes).unwrap();

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes).unwrap();
    let vk_file = VK_FILE.as_str();
    fs::write(format!("{path}{vk_file}"), vk_bytes).unwrap();

    let mut _pk = PK.lock().unwrap();
    *_pk = pk;

    let mut _vk = VK.lock().unwrap();
    *_vk = vk;

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn prove_bn254(param_path: *const c_char) -> bool {
    let path = match utils::path_from_c_str(param_path, "[param_path]") {
        Some(p) => p,
        None => return false,
    };

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let pk = PK.lock().unwrap().clone();

    let attr = vec![F::from(2u64); 50];
    let cond = vec![F::from(1u64); 50];
    let mut chk1 = vec![true; 25];
    chk1.extend_from_slice(&[false; 25]);

    let circuit = Circuit::<F>::new(attr.clone(), cond.clone(), chk1.clone(), 50);

    let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

    let mut proof_byte = Vec::new();
    proof.serialize_compressed(&mut proof_byte).unwrap();
    let prf_file = PRF_FILE.as_str();
    fs::write(format!("{path}{prf_file}"), proof_byte).unwrap();

    let mut _proof = PRF.lock().unwrap();
    *_proof = proof;

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn verify_bn254(param_path: *const c_char) -> bool {
    let path = match utils::path_from_c_str(param_path, "[param_path]") {
        Some(p) => p,
        None => return false,
    };

    let vk = VK.lock().unwrap().clone();

    let pvk = prepare_verifying_key(&vk);

    let proof = PRF.lock().unwrap().clone();

    let cond = [F::from(1u64); 50];

    assert!(
        Groth16::<E>::verify_with_processed_vk(&pvk, &(cond), &proof).unwrap(),
        "[SNARK] Verification failed"
    );

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn get_vk_bn254(param_path: *const c_char) -> *mut c_char {
    let c_string_vk = CString::new(vk_from_file::<E>(string_from_ptr(param_path).as_str()))
        .expect("CString::new failed");
    c_string_vk.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn get_proof_bn254(param_path: *const c_char) -> *mut c_char {
    let c_string_prf = CString::new(proof_from_file::<E>(string_from_ptr(param_path).as_str()))
        .expect("CString::new failed");
    c_string_prf.into_raw()
}

#[test]
fn test_all() {
    let c_path = CString::new("./params/").unwrap();
    let path = c_path.as_ptr();

    assert!(setup_bn254(path, 50));
    assert!(prove_bn254(path));
    assert!(verify_bn254(path));

    let vk_str = get_vk_bn254(path);
    let prf_str = get_proof_bn254(path);

    println!("vk: {:#?}", string_from_ptr(vk_str));
    println!("proof: {:#?}", string_from_ptr(prf_str));
}
