use crate::{BasePrimeField, encryption::*, utils::mimc7::*};

use ark_crypto_primitives::snark::BooleanInputVar;
use ark_ec::{AffineRepr, CurveConfig, Group, pairing::Pairing};
use ark_ff::{
    One, PrimeField,
    biginteger::{BigInteger as _, BigInteger64 as B},
};
use ark_r1cs_std::{
    boolean::Boolean, fields::fp::FpVar, pairing::PairingVar, prelude::*, uint32::UInt32,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError, SynthesisMode},
};
use ark_std::{Zero, fmt::Debug};
use std::{
    borrow::Borrow,
    cmp,
    marker::PhantomData,
    ops::{AddAssign, Mul, MulAssign, Not},
    str::FromStr,
};

// Encrypt-and-prove SNARK Circuit
#[derive(Clone, Debug)]
pub struct TradeCircuit<F: PrimeField> {
    pub attr: Option<Vec<F>>,
    pub sk_s: Option<F>,
    pub cm_old: Option<F>,
    pub nf: F,
    pub len: usize,
    round_keys: Vec<F>,
}

impl<F> TradeCircuit<F>
where
    F: PrimeField,
{
    pub fn get_hash_round_keys() -> Vec<F>
    where
        <F as FromStr>::Err: Debug,
    {
        MiMC7::<F>::round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS)
    }

    pub fn new(attr: Vec<F>, sk_s: F, cm_old: F, nf: F, len: usize) -> Self
    where
        <F as FromStr>::Err: Debug,
    {
        Self {
            attr: Some(attr),
            sk_s: Some(sk_s),
            cm_old: Some(cm_old),
            nf,
            len,
            round_keys: Self::get_hash_round_keys(),
        }
    }

    pub fn mock(len: usize, nf: F) -> Self
    where
        <F as FromStr>::Err: Debug,
    {
        Self {
            attr: Some(vec![F::zero(); len]),
            sk_s: Some(F::zero()),
            cm_old: Some(F::zero()),
            nf,
            len,
            round_keys: Self::get_hash_round_keys(),
        }
    }
}

impl<F> ConstraintSynthesizer<F> for TradeCircuit<F>
where
    F: PrimeField,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let attr = Vec::<FpVar<F>>::new_input(cs.clone(), || {
            self.attr.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let sk_s = FpVar::<F>::new_witness(cs.clone(), || {
            self.sk_s.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let cm_old = FpVar::<F>::new_witness(cs.clone(), || {
            self.cm_old.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let nf = FpVar::<F>::new_constant(cs.clone(), self.nf)?;

        let round_keys = Vec::<FpVar<F>>::new_constant(cs.clone(), self.round_keys)?;

        // ============================ check nf ============================
        fn mimc7_round<F: PrimeField>(
            mut msg: FpVar<F>,
            key: FpVar<F>,
            constant: &FpVar<F>,
        ) -> FpVar<F> {
            msg += key;
            msg += constant;
            let tmp = msg.clone().square().unwrap();
            let mut res = tmp.clone().square().unwrap();
            res *= tmp;
            res *= msg;
            res
        }

        let mut computed_nf = mimc7_round::<F>(cm_old.clone(), sk_s.clone(), &round_keys[0]);

        for i in 1..MIMC7_ROUNDS {
            computed_nf = mimc7_round::<F>(computed_nf, sk_s.clone(), &round_keys[i]);
        }

        computed_nf += cm_old.clone() + sk_s.clone() + sk_s;

        computed_nf.enforce_equal(&nf)?;
        // ==================================================================

        Ok(())
    }
}

#[cfg(test)]
mod trade_circuit {
    use super::{BasePrimeField, TradeCircuit};
    use crate::{
        encryption::{
            cc_enc::CCEnc,
            encryption::{ElGamal, Plaintext},
        },
        utils::mimc7::*,
    };

    use ark_bn254::{Bn254 as E, Fr as F};
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ec::pairing::Pairing;
    use ark_ed_on_bn254::EdwardsConfig as P;
    use ark_ff::PrimeField;
    use ark_groth16::{Groth16, prepare_verifying_key};
    use ark_r1cs_std::prelude::PairingVar;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::fmt::Debug;
    use ark_std::{
        rand::{Rng, RngCore, SeedableRng},
        test_rng,
    };
    use std::convert::TryInto;
    use std::str::FromStr;

    fn test_cp_trade<E: Pairing<ScalarField = F>, F: PrimeField>()
    where
        <F as FromStr>::Err: Debug,
        TradeCircuit<F>: ConstraintSynthesizer<<E as ark_ec::pairing::Pairing>::ScalarField>,
    {
        use crate::cc_snark::{CcGroth16, prepare_verifying_key};
        use crate::linker::{Linker, snark::LinkSnark};
        use ark_std::UniformRand;

        const LEN: usize = 50;

        fn vec_to_arr<T>(v: Vec<T>) -> [T; LEN] {
            v.try_into()
                .unwrap_or_else(|v: Vec<T>| panic!("Cannot convert into an array"))
        }

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let attr = vec![F::from(2u64); LEN]; // [2, 2, ..., 2]
        let cm_old = F::rand(&mut rng);
        let sk_s = F::rand(&mut rng);

        let mimc7_keys = MiMC7::<F>::round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS);

        let nf = MiMC7::<F>::mimc7(cm_old, sk_s, &mimc7_keys);

        // ct
        let enc_pp = ElGamal::<E>::setup(&mut rng).unwrap();
        let (enc_pk, enc_sk, enc_ck) =
            ElGamal::<E>::keygen(&enc_pp, Box::new(LEN), &mut rng).unwrap();
        let (ct, r) = ElGamal::<E>::encrypt(
            &enc_pp,
            &enc_pk,
            &Plaintext::<E> { msg: attr.clone() },
            &mut rng,
        )
        .unwrap();

        // setup
        let circuit = TradeCircuit::<F>::mock(LEN, nf);

        let (cc_ek, cc_vk) = CcGroth16::<E>::circuit_specific_setup(circuit, &mut rng).unwrap();
        let pvk = prepare_verifying_key::<E>(&cc_vk);
        let snark_ck = cc_ek.clone().ck;

        let (link_pp, link_crs) =
            LinkSnark::<E>::setup(&mut rng, LEN, enc_ck.ck.clone(), snark_ck, "trade");
        let (link_ek, link_vk) = LinkSnark::<E>::keygen(&mut rng, &link_pp, link_crs);

        // prove
        let circuit = TradeCircuit::<F>::new(attr.clone(), sk_s, cm_old, nf, LEN);
        let cc_prf = CcGroth16::<E>::prove(&cc_ek, circuit, &mut rng).unwrap();

        let link_witness =
            LinkSnark::<E>::generate_witness(r.randness, attr.clone(), vec![cc_prf.clone().open]);
        let (link_prf, link_cm_aux) =
            LinkSnark::<E>::prove(&mut rng, &link_pp, &link_ek, &link_witness);

        // verify
        assert!(
            CcGroth16::<E>::verify_proof(&pvk, &cc_prf, &vec_to_arr(attr)).unwrap(),
            "[ccGro16] Verification Failed"
        );

        let ct_instance = ct.ct.clone().into_iter().flatten().collect();
        let link_instance = LinkSnark::<E>::generate_instance(ct_instance, cc_prf.cm, link_cm_aux);
        assert!(
            LinkSnark::<E>::verify(&link_pp, &link_vk, &link_instance, &link_prf),
            "[Linker] Verification Failed"
        );

        // decrypt
        let dec_msg = ElGamal::<E>::decrypt(&enc_pp, &enc_sk, &ct).unwrap();
        // #[cfg(all(feature = "print-trace"))]
        // println!("[Decryption] MSG: \n{:#?}", dec_msg);
    }

    #[test]
    fn test_cp_trade_bn254() {
        test_cp_trade::<E, F>()
    }
}
