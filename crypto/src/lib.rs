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
pub mod encryption;
pub mod linker;
pub mod utils;

pub use ark_crypto_primitives::*;
pub use ark_ec::*;
pub use ark_ff::*;
pub use ark_poly::*;

use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
pub use pairing::*;
use rand::{Rng, SeedableRng};

pub(crate) type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
pub(crate) type BasePrimeField<E> =
    <<<E as Pairing>::G1 as CurveGroup>::BaseField as Field>::BasePrimeField;

#[macro_use]
extern crate ark_std;

#[cfg(feature = "r1cs")]
#[macro_use]
extern crate derivative;

use crate::dpp_circuit::DPPCircuit;
use crate::encryption::cc_enc::CCEnc;
use crate::encryption::encryption::{ElGamal, Plaintext};
use crate::encryption::trade_circuit::TradeCircuit;
use crate::utils::{dec_msg_to_string, mimc7::*};
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
use std::str::FromStr;
use std::{
    convert::TryInto,
    ffi::{CString, c_char},
    fs,
    ops::Mul,
    sync::Mutex,
};
use utils::{
    cc_proof_from_file, cc_vk_from_file, cm_from_file, get_file_as_byte_vec, link_proof_from_file,
    link_vk_from_file, path_from_c_str, string_from_ptr,
};

#[macro_use]
extern crate lazy_static;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
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

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct TradePP<E: Pairing> {
    pub cc_pk: ProvingKey<E>,
    pub link_pp: <LinkSnark<E> as Linker<E>>::PP,
    pub link_pk: <LinkSnark<E> as Linker<E>>::EK,
    pub enc_pp: <ElGamal<E> as CCEnc<E>>::Parameters,
    pub enc_pk: <ElGamal<E> as CCEnc<E>>::PublicKey,
    pub enc_ck: <ElGamal<E> as CCEnc<E>>::CommitKey,
}

impl<E: Pairing> Default for TradePP<E> {
    fn default() -> Self {
        Self {
            cc_pk: ProvingKey::<E>::default(),
            link_pp: <LinkSnark<E> as Linker<E>>::PP::default(),
            link_pk: <LinkSnark<E> as Linker<E>>::EK::default(),
            enc_pp: <ElGamal<E> as CCEnc<E>>::Parameters::default(),
            enc_pk: <ElGamal<E> as CCEnc<E>>::PublicKey::default(),
            enc_ck: <ElGamal<E> as CCEnc<E>>::CommitKey::default(),
        }
    }
}

lazy_static! {
    // DPP
    pub static ref PP_FILE: String = "dpp.pp.dat".to_string();
    pub static ref CC_VK_FILE: String = "dpp.cc_vk.dat".to_string();
    pub static ref CC_PRF_FILE: String = "dpp.cc_proof.dat".to_string();
    pub static ref CM_FILE: String = "dpp.cm.dat".to_string();
    pub static ref LINK_VK_FILE: String = "dpp.link_vk.dat".to_string();
    pub static ref LINK_PRF_FILE: String = "dpp.link_proof.dat".to_string();
    pub static ref LINK_CM_FILE: String = "dpp.link_cm.dat".to_string();
    // static ref PARAMS: Mutex<PP<E>> = Mutex::new(PP::<E>::default());
    // static ref CC_VK: Mutex<VerifyingKey<E>> = Mutex::new(VerifyingKey::default());
    // static ref CC_PRF: Mutex<Proof<E>> = Mutex::new(Proof::default());
    // static ref CM: Mutex<<E as Pairing>::G1Affine> =
    //     Mutex::new(<E as Pairing>::G1Affine::default());
    // static ref LINK_VK: Mutex<<LinkSnark<E> as Linker<E>>::VK> =
    //     Mutex::new(<LinkSnark<E> as Linker<E>>::VK::default());
    // static ref LINK_PRF: Mutex<<LinkSnark<E> as Linker<E>>::Proof> =
    //     Mutex::new(<LinkSnark<E> as Linker<E>>::Proof::default());
    // static ref LINK_CM: Mutex<<LinkSnark<E> as Linker<E>>::CM> =
    //     Mutex::new(<LinkSnark<E> as Linker<E>>::CM::default());

    // TRADE
    pub static ref TRADE_PP_FILE: String = "trade.pp.dat".to_string();
    pub static ref TRADE_CC_VK_FILE: String = "trade.cc_vk.dat".to_string();
    pub static ref TRADE_CC_PRF_FILE: String = "trade.cc_proof.dat".to_string();
    pub static ref TRADE_CT_FILE: String = "trade.ct.dat".to_string();
    pub static ref TRADE_LINK_VK_FILE: String = "trade.link_vk.dat".to_string();
    pub static ref TRADE_LINK_PRF_FILE: String = "trade.link_proof.dat".to_string();
    pub static ref TRADE_ENC_SK_FILE: String = "trade.enc_sk.dat".to_string();
    pub static ref TRADE_LINK_CM_FILE: String = "trade.link_cm.dat".to_string();
    static ref TRADE_PARAMS: Mutex<TradePP<E>> = Mutex::new(TradePP::<E>::default());
    static ref TRADE_CC_VK: Mutex<VerifyingKey<E>> = Mutex::new(VerifyingKey::default());
    static ref TRADE_CC_PRF: Mutex<Proof<E>> = Mutex::new(Proof::default());
    static ref TRADE_CT: Mutex<<ElGamal<E> as CCEnc<E>>::Ciphertext> =
        Mutex::new(<ElGamal<E> as CCEnc<E>>::Ciphertext::default());
    static ref TRADE_LINK_VK: Mutex<<LinkSnark<E> as Linker<E>>::VK> =
        Mutex::new(<LinkSnark<E> as Linker<E>>::VK::default());
    static ref TRADE_LINK_PRF: Mutex<<LinkSnark<E> as Linker<E>>::Proof> =
        Mutex::new(<LinkSnark<E> as Linker<E>>::Proof::default());
    static ref TRADE_LINK_CM: Mutex<<LinkSnark<E> as Linker<E>>::CM> =
        Mutex::new(<LinkSnark<E> as Linker<E>>::CM::default());
    static ref TRADE_ENC_SK: Mutex<<ElGamal<E> as CCEnc<E>>::SecretKey> = Mutex::new(<ElGamal<E> as CCEnc<E>>::SecretKey::default());
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

    // let mut cond: Vec<F> = Vec::new();
    // for i in 0..len {
    //     let mut cond_limbs: [u64; 4] = [0; 4];
    //     unsafe {
    //         std::ptr::copy_nonoverlapping(cond_buf.add(4 * i), cond_limbs.as_mut_ptr(), 4);
    //     }
    //     let cond_bigint = BigInt::<4>(cond_limbs);
    //     cond.push(
    //         F::from_bigint(cond_bigint).expect("[Bn2Fr] Out of range (larger than field modulus)"),
    //     );
    // }

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

    let pp = PP {
        cc_pk,
        link_pp,
        link_pk,
        ck,
    };
    let mut pp_bytes = Vec::new();
    pp.serialize_compressed(&mut pp_bytes).unwrap();
    let pp_file = PP_FILE.as_str();
    fs::write(format!("{path}{pp_file}"), pp_bytes).unwrap();

    let mut cc_vk_bytes = Vec::new();
    cc_vk.serialize_compressed(&mut cc_vk_bytes).unwrap();
    let cc_vk_file = CC_VK_FILE.as_str();
    fs::write(format!("{path}{cc_vk_file}"), cc_vk_bytes).unwrap();

    let mut link_vk_bytes = Vec::new();
    link_vk.serialize_compressed(&mut link_vk_bytes).unwrap();
    let link_vk_file = LINK_VK_FILE.as_str();
    fs::write(format!("{path}{link_vk_file}"), link_vk_bytes).unwrap();

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn prove_dpp_bn254(
    param_path: *const c_char,
    attr_buf: *const u64,
    cond_buf: *const u64,
    chk_buf: *const bool,
    // enc_recv_path:  // enc_pp_recv를 enc_pp, enc_pk로 묶어서 link_prove 사용
    len: usize,
) -> bool {
    let path = match utils::path_from_c_str(param_path, "[param_path]") {
        Some(p) => p,
        None => return false,
    };

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let attr_u64 = unsafe { std::slice::from_raw_parts(attr_buf, len).to_vec() };
    let cond_u64 = unsafe { std::slice::from_raw_parts(cond_buf, len).to_vec() };

    let attr: Vec<F> = attr_u64.iter().map(|&x| F::from(x)).collect();
    let cond: Vec<F> = cond_u64.iter().map(|&x| F::from(x)).collect();

    // let mut attr: Vec<F> = Vec::new();
    // for i in 0..len {
    //     let mut attr_limbs: [u64; 4] = [0; 4];
    //     unsafe {
    //         std::ptr::copy_nonoverlapping(attr_buf.add(4 * i), attr_limbs.as_mut_ptr(), 4);
    //     }
    //     let attr_bigint = BigInt::<4>(attr_limbs);
    //     attr.push(
    //         F::from_bigint(attr_bigint).expect("[Bn2Fr] Out of range (larger than field modulus)"),
    //     );
    // }

    // let mut cond: Vec<F> = Vec::new();
    // for i in 0..len {
    //     let mut cond_limbs: [u64; 4] = [0; 4];
    //     unsafe {
    //         std::ptr::copy_nonoverlapping(cond_buf.add(4 * i), cond_limbs.as_mut_ptr(), 4);
    //     }
    //     let cond_bigint = BigInt::<4>(cond_limbs);
    //     cond.push(
    //         F::from_bigint(cond_bigint).expect("[Bn2Fr] Out of range (larger than field modulus)"),
    //     );
    // }

    let chk = unsafe { std::slice::from_raw_parts(chk_buf, len).to_vec() };

    // let pp = PARAMS.lock().unwrap().clone();
    let pp_file = PP_FILE.as_str();
    let raw_pp = get_file_as_byte_vec(&format!("{path}{pp_file}"));
    let pp = PP::<E>::deserialize_compressed(raw_pp.as_slice()).unwrap();

    let circuit = DPPCircuit::<F>::new(attr.clone(), cond.clone(), chk, len);

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

    let mut link_cm_byte = Vec::new();
    link_cm_aux.serialize_compressed(&mut link_cm_byte).unwrap();
    let link_cm_file = LINK_CM_FILE.as_str();
    fs::write(format!("{path}{link_cm_file}"), link_cm_byte).unwrap();

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn verify_dpp_bn254(param_path: *const c_char, len: usize) -> bool {
    let path = match utils::path_from_c_str(param_path, "[param_path]") {
        Some(p) => p,
        None => return false,
    };

    let pp_file = PP_FILE.as_str();
    let raw_pp = get_file_as_byte_vec(&format!("{path}{pp_file}"));
    let pp = PP::<E>::deserialize_compressed(raw_pp.as_slice()).unwrap();

    let cc_prf_file = CC_PRF_FILE.as_str();
    let raw_cc_prf = get_file_as_byte_vec(&format!("{path}{cc_prf_file}"));
    let cc_prf = Proof::<E>::deserialize_compressed(raw_cc_prf.as_slice()).unwrap();

    let link_prf_file = LINK_PRF_FILE.as_str();
    let raw_link_prf = get_file_as_byte_vec(&format!("{path}{link_prf_file}"));
    let link_prf =
        <LinkSnark<E> as Linker<E>>::Proof::deserialize_compressed(raw_link_prf.as_slice())
            .unwrap();

    let cc_vk_file = CC_VK_FILE.as_str();
    let raw_cc_vk = get_file_as_byte_vec(&format!("{path}{cc_vk_file}"));
    let cc_vk = VerifyingKey::<E>::deserialize_compressed(raw_cc_vk.as_slice()).unwrap();
    let pvk = prepare_verifying_key(&cc_vk);

    let link_vk_file = LINK_VK_FILE.as_str();
    let raw_link_vk = get_file_as_byte_vec(&format!("{path}{link_vk_file}"));
    let link_vk =
        <LinkSnark<E> as Linker<E>>::VK::deserialize_compressed(raw_link_vk.as_slice()).unwrap();

    let cm_file = CM_FILE.as_str();
    let raw_cm = get_file_as_byte_vec(&format!("{path}{cm_file}"));
    let cm = <E as Pairing>::G1Affine::deserialize_compressed(raw_cm.as_slice()).unwrap();

    let link_cm_file = LINK_CM_FILE.as_str();
    let raw_link_cm = get_file_as_byte_vec(&format!("{path}{link_cm_file}"));
    let link_cm =
        <LinkSnark<E> as Linker<E>>::CM::deserialize_compressed(raw_link_cm.as_slice()).unwrap();

    let link_instance = LinkSnark::<E>::generate_instance(vec![cm], cc_prf.cm, link_cm);

    let snark_res = CcGroth16::<E>::verify_proof(&pvk, &cc_prf, &[]).unwrap();

    let link_res = LinkSnark::<E>::verify(&pp.link_pp, &link_vk, &link_instance, &link_prf);

    println!("[Verify] SNARK: {}\tLink: {}", snark_res, link_res);

    snark_res && link_res
}

#[unsafe(no_mangle)]
pub extern "C" fn setup_trade_bn254(
    param_path: *const c_char,
    len: usize,
    nf_buf: *const u64,
) -> bool {
    let path = match utils::path_from_c_str(param_path, "[param_path]") {
        Some(p) => p,
        None => return false,
    };

    let mut nf_limbs: [u64; 4] = [0; 4];
    unsafe {
        std::ptr::copy_nonoverlapping(nf_buf, nf_limbs.as_mut_ptr(), 4);
    }
    let nf_bigint = BigInt::<4>(nf_limbs);
    let nf = F::from_bigint(nf_bigint).expect("[Bn2Fr] Out of range (larger than field modulus)");

    let circuit = TradeCircuit::<F>::mock(len, nf);

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let (cc_pk, cc_vk) = CcGroth16::<E>::circuit_specific_setup(circuit, &mut rng).unwrap();

    let enc_pp = ElGamal::<E>::setup(&mut rng).unwrap();
    let (enc_pk, enc_sk, enc_ck) = ElGamal::<E>::keygen(&enc_pp, Box::new(len), &mut rng).unwrap();

    let (link_pp, link_crs) =
        LinkSnark::<E>::setup(&mut rng, len, enc_ck.ck.clone(), cc_pk.clone().ck, "trade");
    let (link_pk, link_vk) = LinkSnark::<E>::keygen(&mut rng, &link_pp, link_crs);

    use std::time::{Duration, Instant};
    let start = Instant::now();
    let pp = TradePP {
        cc_pk,
        link_pp,
        link_pk,
        enc_pp,
        enc_pk,
        enc_ck,
    };
    let mut pp_bytes = Vec::new();
    pp.serialize_compressed(&mut pp_bytes).unwrap();
    let pp_file = TRADE_PP_FILE.as_str();
    fs::write(format!("{path}{pp_file}"), pp_bytes).unwrap();
    println!("Writing pp: \t{:#?}", start.elapsed());

    let mut cc_vk_bytes = Vec::new();
    cc_vk.serialize_compressed(&mut cc_vk_bytes).unwrap();
    let cc_vk_file = TRADE_CC_VK_FILE.as_str();
    fs::write(format!("{path}{cc_vk_file}"), cc_vk_bytes).unwrap();

    let mut link_vk_bytes = Vec::new();
    link_vk.serialize_compressed(&mut link_vk_bytes).unwrap();
    let link_vk_file = TRADE_LINK_VK_FILE.as_str();
    fs::write(format!("{path}{link_vk_file}"), link_vk_bytes).unwrap();

    let mut enc_sk_bytes = Vec::new();
    enc_sk.serialize_compressed(&mut enc_sk_bytes).unwrap();
    let enc_sk_file = TRADE_ENC_SK_FILE.as_str();
    fs::write(format!("{path}{enc_sk_file}"), enc_sk_bytes).unwrap();

    // let mut _pp = TRADE_PARAMS.lock().unwrap();
    // *_pp = TradePP {
    //     cc_pk,
    //     link_pp,
    //     link_pk,
    //     enc_pp,
    //     enc_pk,
    //     enc_ck,
    // };

    // let mut _cc_vk = TRADE_CC_VK.lock().unwrap();
    // *_cc_vk = cc_vk;

    // let mut _link_vk = TRADE_LINK_VK.lock().unwrap();
    // *_link_vk = link_vk;

    // let mut _enc_sk = TRADE_ENC_SK.lock().unwrap();
    // *_enc_sk = enc_sk;

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn prove_trade_bn254(
    param_path: *const c_char,
    attr_buf: *const u64,
    sk_s_buf: *const u64,
    cm_old_x_buf: *const u64,
    cm_old_y_buf: *const u64,
    nf_buf: *const u64,
    len: usize,
) -> bool {
    let path = match utils::path_from_c_str(param_path, "[param_path]") {
        Some(p) => p,
        None => return false,
    };

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let attr_u64 = unsafe { std::slice::from_raw_parts(attr_buf, len).to_vec() };
    let attr: Vec<F> = attr_u64.iter().map(|&x| F::from(x)).collect();

    // let mut attr: Vec<F> = Vec::new();
    // for i in 0..len {
    //     let mut attr_limbs: [u64; 4] = [0; 4];
    //     unsafe {
    //         std::ptr::copy_nonoverlapping(attr_buf.add(4 * i), attr_limbs.as_mut_ptr(), 4);
    //     }
    //     let attr_bigint = BigInt::<4>(attr_limbs);
    //     attr.push(
    //         F::from_bigint(attr_bigint).expect("[Bn2Fr] Out of range (larger than field modulus)"),
    //     );
    // }

    let mut sk_s_limbs: [u64; 4] = [0; 4];
    unsafe {
        std::ptr::copy_nonoverlapping(sk_s_buf, sk_s_limbs.as_mut_ptr(), 4);
    }
    let sk_s_bigint = BigInt::<4>(sk_s_limbs);
    let sk_s =
        F::from_bigint(sk_s_bigint).expect("[Bn2Fr] Out of range (larger than field modulus)");

    let mut cm_old_x_limbs: [u64; 4] = [0; 4];
    unsafe {
        std::ptr::copy_nonoverlapping(cm_old_x_buf, cm_old_x_limbs.as_mut_ptr(), 4);
    }
    let cm_old_x_bigint = BigInt::<4>(cm_old_x_limbs);
    let cm_old_x =
        F::from_bigint(cm_old_x_bigint).expect("[Bn2Fr] Out of range (larger than field modulus)");

    let mut cm_old_y_limbs: [u64; 4] = [0; 4];
    unsafe {
        std::ptr::copy_nonoverlapping(cm_old_y_buf, cm_old_y_limbs.as_mut_ptr(), 4);
    }
    let cm_old_y_bigint = BigInt::<4>(cm_old_y_limbs);
    let cm_old_y =
        F::from_bigint(cm_old_y_bigint).expect("[Bn2Fr] Out of range (larger than field modulus)");

    let mut nf_limbs: [u64; 4] = [0; 4];
    unsafe {
        std::ptr::copy_nonoverlapping(nf_buf, nf_limbs.as_mut_ptr(), 4);
    }
    let nf_bigint = BigInt::<4>(nf_limbs);
    let nf = F::from_bigint(nf_bigint).expect("[Bn2Fr] Out of range (larger than field modulus)");

    // let pp = TRADE_PARAMS.lock().unwrap().clone();
    use std::time::{Duration, Instant};
    let start = Instant::now();
    let pp_file = TRADE_PP_FILE.as_str();
    let raw_pp = get_file_as_byte_vec(&format!("{path}{pp_file}"));
    let pp = TradePP::<E>::deserialize_compressed(raw_pp.as_slice()).unwrap();
    println!("Reading pp: \t{:#?}", start.elapsed());

    let circuit = TradeCircuit::<F>::new(attr.clone(), sk_s, cm_old_x, cm_old_y, nf, len);

    let cc_prf = CcGroth16::<E>::prove(&pp.cc_pk, circuit, &mut rng).unwrap();

    let (ct, r) = ElGamal::<E>::encrypt(
        &pp.enc_pp,
        &pp.enc_pk,
        &Plaintext::<E> { msg: attr.clone() },
        &mut rng,
    )
    .unwrap();

    let link_witness =
        LinkSnark::<E>::generate_witness(r.randness, attr, vec![cc_prf.clone().open]);
    let (link_prf, link_cm_aux) =
        LinkSnark::<E>::prove(&mut rng, &pp.link_pp, &pp.link_pk, &link_witness);

    let mut cc_prf_byte = Vec::new();
    cc_prf.serialize_compressed(&mut cc_prf_byte).unwrap();
    let cc_prf_file = TRADE_CC_PRF_FILE.as_str();
    fs::write(format!("{path}{cc_prf_file}"), cc_prf_byte).unwrap();

    let mut link_prf_byte = Vec::new();
    link_prf.serialize_compressed(&mut link_prf_byte).unwrap();
    let link_prf_file = TRADE_LINK_PRF_FILE.as_str();
    fs::write(format!("{path}{link_prf_file}"), link_prf_byte).unwrap();

    let mut ct_byte = Vec::new();
    ct.serialize_compressed(&mut ct_byte).unwrap();
    let ct_file = TRADE_CT_FILE.as_str();
    fs::write(format!("{path}{ct_file}"), ct_byte).unwrap();

    let mut link_cm_byte = Vec::new();
    link_cm_aux.serialize_compressed(&mut link_cm_byte).unwrap();
    let link_cm_file = TRADE_LINK_CM_FILE.as_str();
    fs::write(format!("{path}{link_cm_file}"), link_cm_byte).unwrap();

    // let mut _ct = TRADE_CT.lock().unwrap();
    // *_ct = ct;

    // let mut _cc_prf = TRADE_CC_PRF.lock().unwrap();
    // *_cc_prf = cc_prf;

    // let mut _link_prf = TRADE_LINK_PRF.lock().unwrap();
    // *_link_prf = link_prf;

    // let mut _link_cm = TRADE_LINK_CM.lock().unwrap();
    // *_link_cm = link_cm_aux;

    true
}

#[unsafe(no_mangle)]
pub extern "C" fn verify_trade_bn254(param_path: *const c_char, len: usize) -> bool {
    let path = match utils::path_from_c_str(param_path, "[param_path]") {
        Some(p) => p,
        None => return false,
    };

    // let pp = TRADE_PARAMS.lock().unwrap().clone();

    // let cc_vk = TRADE_CC_VK.lock().unwrap().clone();

    // let pvk = prepare_verifying_key(&cc_vk);

    // let cc_prf = TRADE_CC_PRF.lock().unwrap().clone();

    // let ct = TRADE_CT.lock().unwrap().clone();

    // let link_vk = TRADE_LINK_VK.lock().unwrap().clone();

    // let link_prf = TRADE_LINK_PRF.lock().unwrap().clone();

    // let link_cm = TRADE_LINK_CM.lock().unwrap().clone();

    // let ct_instance = ct.ct.clone().into_iter().flatten().collect();

    let pp_file = TRADE_PP_FILE.as_str();
    let raw_pp = get_file_as_byte_vec(&format!("{path}{pp_file}"));
    let pp = TradePP::<E>::deserialize_compressed(raw_pp.as_slice()).unwrap();

    let cc_prf_file = TRADE_CC_PRF_FILE.as_str();
    let raw_cc_prf = get_file_as_byte_vec(&format!("{path}{cc_prf_file}"));
    let cc_prf = Proof::<E>::deserialize_compressed(raw_cc_prf.as_slice()).unwrap();

    let link_prf_file = TRADE_LINK_PRF_FILE.as_str();
    let raw_link_prf = get_file_as_byte_vec(&format!("{path}{link_prf_file}"));
    let link_prf =
        <LinkSnark<E> as Linker<E>>::Proof::deserialize_compressed(raw_link_prf.as_slice())
            .unwrap();

    let cc_vk_file = TRADE_CC_VK_FILE.as_str();
    let raw_cc_vk = get_file_as_byte_vec(&format!("{path}{cc_vk_file}"));
    let cc_vk = VerifyingKey::<E>::deserialize_compressed(raw_cc_vk.as_slice()).unwrap();
    let pvk = prepare_verifying_key(&cc_vk);

    let link_vk_file = TRADE_LINK_VK_FILE.as_str();
    let raw_link_vk = get_file_as_byte_vec(&format!("{path}{link_vk_file}"));
    let link_vk =
        <LinkSnark<E> as Linker<E>>::VK::deserialize_compressed(raw_link_vk.as_slice()).unwrap();

    let ct_file = TRADE_CT_FILE.as_str();
    let raw_ct = get_file_as_byte_vec(&format!("{path}{ct_file}"));
    let ct =
        <ElGamal<E> as CCEnc<E>>::Ciphertext::deserialize_compressed(raw_ct.as_slice()).unwrap();
    let ct_instance = ct.ct.clone().into_iter().flatten().collect();

    let link_cm_file = TRADE_LINK_CM_FILE.as_str();
    let raw_link_cm = get_file_as_byte_vec(&format!("{path}{link_cm_file}"));
    let link_cm =
        <LinkSnark<E> as Linker<E>>::CM::deserialize_compressed(raw_link_cm.as_slice()).unwrap();

    let link_instance = LinkSnark::<E>::generate_instance(ct_instance, cc_prf.cm, link_cm);

    let snark_res = CcGroth16::<E>::verify_proof(&pvk, &cc_prf, &[]).unwrap();

    let link_res = LinkSnark::<E>::verify(&pp.link_pp, &link_vk, &link_instance, &link_prf);

    println!("[Verify] SNARK: {}\tLink: {}", snark_res, link_res);

    snark_res && link_res

    // CcGroth16::<E>::verify_proof(&pvk, &cc_prf, &[]).unwrap()
    //     && LinkSnark::<E>::verify(&pp.link_pp, &link_vk, &link_instance, &link_prf)
}

#[unsafe(no_mangle)]
pub extern "C" fn decrypt_trade_bn254(param_path: *const c_char) -> *mut c_char {
    // let pp = TRADE_PARAMS.lock().unwrap().clone();

    // let enc_sk = TRADE_ENC_SK.lock().unwrap().clone();

    // let ct = TRADE_CT.lock().unwrap().clone();

    let path = match utils::path_from_c_str(param_path, "[param_path]") {
        Some(p) => p,
        None => {
            return CString::from_str("[ENC] Decryption Failed")
                .unwrap()
                .into_raw();
        }
    };

    let pp_file = TRADE_PP_FILE.as_str();
    let raw_pp = get_file_as_byte_vec(&format!("{path}{pp_file}"));
    let pp = TradePP::<E>::deserialize_compressed(raw_pp.as_slice()).unwrap();

    let enc_sk_file = TRADE_ENC_SK_FILE.as_str();
    let raw_enc_sk = get_file_as_byte_vec(&format!("{path}{enc_sk_file}"));
    let enc_sk =
        <ElGamal<E> as CCEnc<E>>::SecretKey::deserialize_compressed(raw_enc_sk.as_slice()).unwrap();

    let ct_file = TRADE_CT_FILE.as_str();
    let raw_ct = get_file_as_byte_vec(&format!("{path}{ct_file}"));
    let ct =
        <ElGamal<E> as CCEnc<E>>::Ciphertext::deserialize_compressed(raw_ct.as_slice()).unwrap();

    let dec_msg = <ElGamal<E> as CCEnc<E>>::decrypt(&pp.enc_pp, &enc_sk, &ct).unwrap();

    let c_string_dec_msg = CString::new(dec_msg_to_string(dec_msg)).expect("CString::new failed");

    c_string_dec_msg.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn get_cc_vk_bn254(param_path: *const c_char, mode: bool) -> *mut c_char {
    let c_string_vk = CString::new(cc_vk_from_file::<E>(
        string_from_ptr(param_path).as_str(),
        mode,
    ))
    .expect("CString::new failed");
    c_string_vk.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn get_cc_proof_bn254(param_path: *const c_char, mode: bool) -> *mut c_char {
    let c_string_prf = CString::new(cc_proof_from_file::<E>(
        string_from_ptr(param_path).as_str(),
        mode,
    ))
    .expect("CString::new failed");
    c_string_prf.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn get_link_vk_bn254(param_path: *const c_char, mode: bool) -> *mut c_char {
    let c_string_vk = CString::new(link_vk_from_file::<E>(
        string_from_ptr(param_path).as_str(),
        mode,
    ))
    .expect("CString::new failed");
    c_string_vk.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn get_link_proof_bn254(param_path: *const c_char, mode: bool) -> *mut c_char {
    let c_string_prf = CString::new(link_proof_from_file::<E>(
        string_from_ptr(param_path).as_str(),
        mode,
    ))
    .expect("CString::new failed");
    c_string_prf.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn get_cm_bn254(param_path: *const c_char) -> *mut c_char {
    let c_string_cm = CString::new(cm_from_file::<E>(string_from_ptr(param_path).as_str()))
        .expect("CString::new failed");
    c_string_cm.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn get_nf(
    sk_s_buf: *const u64,
    cm_old_x_buf: *const u64,
    cm_old_y_buf: *const u64,
    nf: *mut u64,
) {
    let mut sk_s_limbs: [u64; 4] = [0; 4];
    unsafe {
        std::ptr::copy_nonoverlapping(sk_s_buf, sk_s_limbs.as_mut_ptr(), 4);
    }
    let sk_s_bigint = BigInt::<4>(sk_s_limbs);
    let sk_s =
        F::from_bigint(sk_s_bigint).expect("[Bn2Fr] Out of range (larger than field modulus)");

    let mut cm_old_x_limbs: [u64; 4] = [0; 4];
    unsafe {
        std::ptr::copy_nonoverlapping(cm_old_x_buf, cm_old_x_limbs.as_mut_ptr(), 4);
    }
    let cm_old_x_bigint = BigInt::<4>(cm_old_x_limbs);
    let cm_old_x =
        F::from_bigint(cm_old_x_bigint).expect("[Bn2Fr] Out of range (larger than field modulus)");

    let mut cm_old_y_limbs: [u64; 4] = [0; 4];
    unsafe {
        std::ptr::copy_nonoverlapping(cm_old_y_buf, cm_old_y_limbs.as_mut_ptr(), 4);
    }
    let cm_old_y_bigint = BigInt::<4>(cm_old_y_limbs);
    let cm_old_y =
        F::from_bigint(cm_old_y_bigint).expect("[Bn2Fr] Out of range (larger than field modulus)");

    let constants = MiMC7::<F>::round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS);
    let mut hash = MiMC7::<F>::mimc7(cm_old_x, cm_old_y, &constants);
    hash = MiMC7::<F>::mimc7(hash, sk_s, &constants);
    let limb = hash.into_bigint().0;

    unsafe {
        for i in 0..4 {
            *nf.add(i) = limb[i];
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn get_random_values(mut val_pt: *mut u64) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let val_fr = F::rand(&mut rng);
    let val = val_fr.into_bigint().0;

    unsafe {
        std::ptr::copy_nonoverlapping(val.as_ptr(), val_pt, 4);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn format_fr(mut val_pt: *mut u64) {
    let mut limbs: [u64; 4] = [0; 4];
    unsafe {
        std::ptr::copy_nonoverlapping(val_pt, limbs.as_mut_ptr(), 4);
    }
    let val_bigint = BigInt::<4>(limbs);

    let val_fr =
        F::from_bigint(val_bigint).expect("[Bn2Fr] Out of range (larger than field modulus)");
    let mut res = val_fr.into_bigint().0;
    for i in 0..4 {
        unsafe {
            *val_pt.add(i) = res[i];
        }
    }
}

#[test]
fn test_dpp() {
    let c_path = CString::new("./params/").unwrap();
    let path = c_path.as_ptr();
    const LEN: usize = 50;

    let attr = vec![2u64; LEN];
    let cond = vec![1u64; LEN];

    // let mut attr = Vec::new();
    // let attr_i = vec![2u64, 0u64, 0u64, 0u64];
    // for _ in 0..LEN {
    //     attr.extend(&attr_i);
    // }

    // let mut cond = Vec::new();
    // let cond_i = vec![1u64, 0u64, 0u64, 0u64];
    // for _ in 0..LEN / 2 {
    //     cond.extend(&cond_i);
    // }
    // let cond_i = vec![3u64, 0u64, 0u64, 0u64];
    // for _ in 0..LEN / 2 {
    //     cond.extend(&cond_i);
    // }

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
    assert!(verify_dpp_bn254(path, LEN), "[DPP] Verification failed");

    let cc_vk_str = get_cc_vk_bn254(path, false);
    let cc_prf_str = get_cc_proof_bn254(path, false);
    println!("cc_vk: {}", unsafe {
        std::ffi::CStr::from_ptr(cc_vk_str).to_string_lossy()
    });
    println!("cc_proof: {}", unsafe {
        std::ffi::CStr::from_ptr(cc_prf_str).to_string_lossy()
    });

    let link_vk_str = get_link_vk_bn254(path, false);
    let link_prf_str = get_link_proof_bn254(path, false);
    println!("link_vk: {}", unsafe {
        std::ffi::CStr::from_ptr(link_vk_str).to_string_lossy()
    });
    println!("link_proof: {}", unsafe {
        std::ffi::CStr::from_ptr(link_prf_str).to_string_lossy()
    });
}

#[test]
fn test_trade() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let c_path = CString::new("./params/").unwrap();
    let path = c_path.as_ptr();
    const LEN: usize = 50;

    let attr = vec![2u64; LEN];
    // let mut attr = Vec::new();
    // let attr_i = vec![2u64, 0u64, 0u64, 0u64];
    // for _ in 0..LEN {
    //     attr.extend(&attr_i);
    // }

    let mut cm_old_x_u64: [u64; 4] = [0; 4];
    let mut cm_old_y_u64: [u64; 4] = [0; 4];
    let mut sk_s_u64: [u64; 4] = [0; 4];
    get_random_values(cm_old_x_u64.as_mut_ptr());
    get_random_values(cm_old_y_u64.as_mut_ptr());
    get_random_values(sk_s_u64.as_mut_ptr());
    let cm_old_x_bigint = BigInt::<4>(cm_old_x_u64);
    let cm_old_y_bigint = BigInt::<4>(cm_old_y_u64);
    let sk_s_bigint = BigInt::<4>(sk_s_u64);
    let cm_old_x = F::from(cm_old_x_bigint);
    let cm_old_y = F::from(cm_old_y_bigint);
    let sk_s = F::from(sk_s_bigint);

    let mimc7_keys = MiMC7::<F>::round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS);

    let mut nf: [u64; 4] = [0; 4];
    get_nf(
        sk_s_u64.as_ptr(),
        cm_old_x_u64.as_ptr(),
        cm_old_y_u64.as_ptr(),
        nf.as_mut_ptr(),
    );
    // let nf_fr = MiMC7::<F>::mimc7(cm_old, sk_s, &mimc7_keys);

    // let nf = nf_fr.into_bigint().0;

    println!("[Trade::Test]");

    assert!(
        setup_trade_bn254(path, LEN, nf.as_ptr()),
        "[Trade] Setup failed"
    );
    assert!(
        prove_trade_bn254(
            path,
            attr.as_ptr(),
            sk_s_u64.as_ptr(),
            cm_old_x_u64.as_ptr(),
            cm_old_y_u64.as_ptr(),
            nf.as_ptr(),
            LEN
        ),
        "[Trade] Proof generation failed"
    );
    assert!(verify_trade_bn254(path, LEN), "[Trade] Verification failed");

    let cc_vk_str = get_cc_vk_bn254(path, true);
    let cc_prf_str = get_cc_proof_bn254(path, true);
    println!("cc_vk: {}", unsafe {
        std::ffi::CStr::from_ptr(cc_vk_str).to_string_lossy()
    });
    println!("cc_proof: {}", unsafe {
        std::ffi::CStr::from_ptr(cc_prf_str).to_string_lossy()
    });

    let link_vk_str = get_link_vk_bn254(path, true);
    let link_prf_str = get_link_proof_bn254(path, true);
    println!("link_vk: {}", unsafe {
        std::ffi::CStr::from_ptr(link_vk_str).to_string_lossy()
    });
    println!("link_proof: {}", unsafe {
        std::ffi::CStr::from_ptr(link_prf_str).to_string_lossy()
    });

    println!("[Dec] msg: {:#?}", decrypt_trade_bn254(path));
}

#[test]
fn format_over_bn254() {
    let mut rng = test_rng();
    let mut test_val: [u64; 4] = [0; 4];
    for i in 0..4 {
        test_val[i] = rng.r#gen();
        while i == 3 && test_val[i] > 1u64 << 62 {
            test_val[i] = rng.r#gen();
        }
    }
    println!("[Val] {:#?}", test_val);
    let formatted_val = format_fr(test_val.as_mut_ptr());
    println!("[Val] {:#?}", test_val);
}
