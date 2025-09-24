#![allow(
    dead_code,
    unused_imports,
    unused_mut,
    unused_variables,
    unused_macros,
    unused_assignments,
    unreachable_patterns
)]

pub mod cc_snark;
pub mod dpp_circuit;
pub mod linker;
// pub mod trade_circuit;
// pub mod trade_data_structure;
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
    <<<E as Pairing>::G1 as CurveGroup>::BaseField as Field>::BasePrimeField;

#[macro_use]
extern crate ark_std;

#[cfg(feature = "r1cs")]
#[macro_use]
extern crate derivative;

use crate::dpp_circuit::DPPCircuit;
use crate::{
    cc_snark::{
        CcGroth16,
        data_structure::{Proof, ProvingKey, VerifyingKey},
        prepare_verifying_key,
    },
    linker::{Linker, snark::LinkSnark},
};
use ark_bn254::{Bn254 as E, Fr as F};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
// use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey, prepare_verifying_key};
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
    cc_proof_from_file, cc_vk_from_file, get_file_as_byte_vec, link_proof_from_file,
    link_vk_from_file, path_from_c_str, string_from_ptr,
};

#[macro_use]
extern crate lazy_static;

#[derive(Clone, Debug)]
pub struct PP<E: Pairing> {
    pub cc_pk: ProvingKey<E>,
    pub link_pp: <LinkSnark<E> as Linker<E>>::PP,
    pub link_pk: <LinkSnark<E> as Linker<E>>::EK,
    pub ck: Vec<E::G1Affine>,
}

impl<E: Pairing> Default for PP<E> {
    fn default() -> Self {
        Self {
            cc_pk: ProvingKey::<E>::default(),
            link_pp: <LinkSnark<E> as Linker<E>>::PP::default(),
            link_pk: <LinkSnark<E> as Linker<E>>::EK::default(),
            ck: Vec::<E::G1Affine>::default(),
        }
    }
}

lazy_static! {
    pub static ref CC_VK_FILE: String = "cc_vk.dat".to_string();
    pub static ref CC_PRF_FILE: String = "cc_proof.dat".to_string();
    pub static ref CM_FILE: String = "cm.dat".to_string();
    pub static ref LINK_VK_FILE: String = "link_vk.dat".to_string();
    pub static ref LINK_PRF_FILE: String = "link_proof.dat".to_string();
    static ref PARAMS: Mutex<PP<E>> = Mutex::new(PP::<E>::default());
    static ref CC_VK: Mutex<VerifyingKey<E>> = Mutex::new(VerifyingKey::default());
    static ref CC_PRF: Mutex<Proof<E>> = Mutex::new(Proof::default());
    static ref CM: Mutex<<E as Pairing>::G1Affine> =
        Mutex::new(<E as Pairing>::G1Affine::default());
    static ref LINK_VK: Mutex<<LinkSnark<E> as Linker<E>>::VK> =
        Mutex::new(<LinkSnark<E> as Linker<E>>::VK::default());
    static ref LINK_PRF: Mutex<<LinkSnark<E> as Linker<E>>::Proof> =
        Mutex::new(<LinkSnark<E> as Linker<E>>::Proof::default());
    static ref LINK_CM: Mutex<<LinkSnark<E> as Linker<E>>::CM> =
        Mutex::new(<LinkSnark<E> as Linker<E>>::CM::default());
}

#[unsafe(no_mangle)]
pub extern "C" fn setup_dpp_bn254(
    param_path: *const c_char,
    len: usize,
    cond_buf: *const u64,
) -> bool {
    let path = match utils::path_from_c_str(param_path, "[param_path]") {
        Some(p) => p,
        None => return false,
    };
    let cond_u64 = unsafe { std::slice::from_raw_parts(cond_buf, len).to_vec() };
    let cond: Vec<F> = cond_u64.iter().map(|&x| F::from(x)).collect();

    let circuit = DPPCircuit::<F>::mock(len, cond);

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let (cc_pk, cc_vk) = CcGroth16::<E>::circuit_specific_setup(circuit, &mut rng).unwrap();

    let mut ck = Vec::new();

    for _ in 0..len + 1 {
        ck.push(<E as Pairing>::G1Affine::rand(&mut rng));
    }

    let (link_pp, link_crs) =
        LinkSnark::<E>::setup(&mut rng, len, ck.clone(), cc_pk.clone().ck, "dpp");
    let (link_pk, link_vk) = LinkSnark::<E>::keygen(&mut rng, &link_pp, link_crs);

    let mut cc_vk_bytes = Vec::new();
    cc_vk.serialize_compressed(&mut cc_vk_bytes).unwrap();
    let cc_vk_file = CC_VK_FILE.as_str();
    fs::write(format!("{path}{cc_vk_file}"), cc_vk_bytes).unwrap();

    let mut link_vk_bytes = Vec::new();
    link_vk.serialize_compressed(&mut link_vk_bytes).unwrap();
    let link_vk_file = LINK_VK_FILE.as_str();
    fs::write(format!("{path}{link_vk_file}"), link_vk_bytes).unwrap();

    let mut _pp = PARAMS.lock().unwrap();
    *_pp = PP {
        cc_pk,
        link_pp,
        link_pk,
        ck,
    };

    let mut _cc_vk = CC_VK.lock().unwrap();
    *_cc_vk = cc_vk;

    let mut _link_vk = LINK_VK.lock().unwrap();
    *_link_vk = link_vk;

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn prove_dpp_bn254(
    param_path: *const c_char,
    attr_buf: *const u64,
    cond_buf: *const u64,
    chk_buf: *const bool,
    len: usize,
) -> bool {
    let path = match utils::path_from_c_str(param_path, "[param_path]") {
        Some(p) => p,
        None => return false,
    };

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let attr_u64 = unsafe { std::slice::from_raw_parts(attr_buf, len).to_vec() };
    let cond_u64 = unsafe { std::slice::from_raw_parts(cond_buf, len).to_vec() };
    let chk = unsafe { std::slice::from_raw_parts(chk_buf, len).to_vec() };

    let attr: Vec<F> = attr_u64.iter().map(|&x| F::from(x)).collect();
    let cond: Vec<F> = cond_u64.iter().map(|&x| F::from(x)).collect();

    let pp = PARAMS.lock().unwrap().clone();

    let circuit = DPPCircuit::<F>::new(attr.clone(), cond.clone(), chk, 50);

    let cc_prf = CcGroth16::<E>::prove(&pp.cc_pk, circuit, &mut rng).unwrap();

    let o = <E as Pairing>::ScalarField::rand(&mut rng);
    let attr_repr = attr.iter().map(|s| s.into_bigint()).collect::<Vec<_>>();
    let cm_proj = <E as Pairing>::G1::msm_bigint(&pp.ck[1..], &attr_repr);
    let cm: <E as Pairing>::G1Affine = (cm_proj + pp.ck[0].into_group() * o.clone()).into();

    let link_witness = LinkSnark::<E>::generate_witness(vec![o], attr, vec![cc_prf.clone().open]);
    let (link_prf, link_cm_aux) =
        LinkSnark::<E>::prove(&mut rng, &pp.link_pp, &pp.link_pk, &link_witness);

    let mut cc_prf_byte = Vec::new();
    cc_prf.serialize_compressed(&mut cc_prf_byte).unwrap();
    let cc_prf_file = CC_PRF_FILE.as_str();
    fs::write(format!("{path}{cc_prf_file}"), cc_prf_byte).unwrap();

    let mut link_prf_byte = Vec::new();
    link_prf.serialize_compressed(&mut link_prf_byte).unwrap();
    let link_prf_file = LINK_PRF_FILE.as_str();
    fs::write(format!("{path}{link_prf_file}"), link_prf_byte).unwrap();

    let mut cm_byte = Vec::new();
    cm.serialize_compressed(&mut cm_byte).unwrap();
    let cm_file = CM_FILE.as_str();
    fs::write(format!("{path}{cm_file}"), cm_byte).unwrap();

    let mut _cc_prf = CC_PRF.lock().unwrap();
    *_cc_prf = cc_prf;

    let mut _link_prf = LINK_PRF.lock().unwrap();
    *_link_prf = link_prf;

    let mut _link_cm = LINK_CM.lock().unwrap();
    *_link_cm = link_cm_aux;

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn verify_dpp_bn254(
    param_path: *const c_char,
    cond_buf: *const u64,
    len: usize,
) -> bool {
    let path = match utils::path_from_c_str(param_path, "[param_path]") {
        Some(p) => p,
        None => return false,
    };
    let cond_u64 = unsafe { std::slice::from_raw_parts(cond_buf, len).to_vec() };

    let cond: Vec<F> = cond_u64.iter().map(|&x| F::from(x)).collect();

    let pp = PARAMS.lock().unwrap().clone();

    let cc_vk = CC_VK.lock().unwrap().clone();

    let pvk = prepare_verifying_key(&cc_vk);

    let cc_prf = CC_PRF.lock().unwrap().clone();

    let cm = CM.lock().unwrap().clone();

    let link_vk = LINK_VK.lock().unwrap().clone();

    let link_prf = LINK_PRF.lock().unwrap().clone();

    let link_cm = LINK_CM.lock().unwrap().clone();

    let link_instance = LinkSnark::<E>::generate_instance(vec![cm], cc_prf.cm, link_cm);

    assert!(
        CcGroth16::<E>::verify_proof(&pvk, &cc_prf, &(cond)).unwrap(),
        "[ccSNARK] Verification failed"
    );

    assert!(
        LinkSnark::<E>::verify(&pp.link_pp, &link_vk, &link_instance, &link_prf),
        "[Linker] Verification failed"
    );

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn get_cc_vk_bn254(param_path: *const c_char) -> *mut c_char {
    let c_string_vk = CString::new(cc_vk_from_file::<E>(string_from_ptr(param_path).as_str()))
        .expect("CString::new failed");
    c_string_vk.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn get_cc_proof_bn254(param_path: *const c_char) -> *mut c_char {
    let c_string_prf = CString::new(cc_proof_from_file::<E>(
        string_from_ptr(param_path).as_str(),
    ))
    .expect("CString::new failed");
    c_string_prf.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn get_link_vk_bn254(param_path: *const c_char) -> *mut c_char {
    let c_string_vk = CString::new(link_vk_from_file::<E>(string_from_ptr(param_path).as_str()))
        .expect("CString::new failed");
    c_string_vk.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn get_link_proof_bn254(param_path: *const c_char) -> *mut c_char {
    let c_string_prf = CString::new(link_proof_from_file::<E>(
        string_from_ptr(param_path).as_str(),
    ))
    .expect("CString::new failed");
    c_string_prf.into_raw()
}

#[test]
fn test_all() {
    let c_path = CString::new("./params/").unwrap();
    let path = c_path.as_ptr();
    const LEN: usize = 50;

    let attr = vec![2u64; LEN];
    let cond = vec![1u64; LEN];
    let mut chk1 = vec![true; LEN / 2];
    chk1.extend_from_slice(&[false; LEN / 2]);

    assert!(
        setup_dpp_bn254(path, LEN, cond.as_ptr()),
        "[DPP] Setup failed"
    );
    assert!(
        prove_dpp_bn254(path, attr.as_ptr(), cond.as_ptr(), chk1.as_ptr(), LEN),
        "[DPP] Proof generation failed"
    );
    assert!(
        verify_dpp_bn254(path, attr.as_ptr(), LEN),
        "[DPP] Verification failed"
    );

    let cc_vk_str = get_cc_vk_bn254(path);
    let cc_prf_str = get_cc_proof_bn254(path);
    println!("cc_vk: {}", unsafe {
        std::ffi::CStr::from_ptr(cc_vk_str).to_string_lossy()
    });
    println!("cc_proof: {}", unsafe {
        std::ffi::CStr::from_ptr(cc_prf_str).to_string_lossy()
    });

    let link_vk_str = get_link_vk_bn254(path);
    let link_prf_str = get_link_proof_bn254(path);
    println!("link_vk: {}", unsafe {
        std::ffi::CStr::from_ptr(link_vk_str).to_string_lossy()
    });
    println!("link_proof: {}", unsafe {
        std::ffi::CStr::from_ptr(link_prf_str).to_string_lossy()
    });
}
