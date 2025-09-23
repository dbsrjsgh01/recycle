use crate::utils::mimc7::*;

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
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, SynthesisMode},
};
use ark_std::{Zero, fmt::Debug};
use std::{
    cmp,
    marker::PhantomData,
    ops::{AddAssign, Mul, MulAssign, Not},
    str::FromStr,
};

// 해야할 일
// 1. cpSNARK
// 2. Input 더 뭐 넣을지

#[derive(Clone, Debug)]
pub struct TradeCircuit<E: Pairing, P: PairingVar<E, E::ScalarField>> {
    pub attr: Option<Vec<E::ScalarField>>,
    pub sk_s: Option<E::ScalarField>,
    pub nf: Option<E::ScalarField>,
    pub ct: Option<Vec<E::G1Affine>>,
    pub len: usize,
    round_keys: Vec<E::ScalarField>,
    _cv: PhantomData<P>,
}

impl<E, P> TradeCircuit<E, P>
where
    E: Pairing,
    P: PairingVar<E, E::ScalarField>,
{
    pub fn get_hash_round_keys() -> Vec<E::ScalarField>
    where
        <E::ScalarField as FromStr>::Err: Debug,
    {
        MiMC7::<E::ScalarField>::round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS)
    }

    pub fn new(
        attr: Vec<E::ScalarField>,
        sk_s: E::ScalarField,
        nf: E::ScalarField,
        len: usize,
        ct: Vec<E::G1Affine>,
    ) -> Self
    where
        <E::ScalarField as FromStr>::Err: Debug,
    {
        Self {
            attr: Some(attr),
            sk_s: Some(sk_s),
            nf: Some(nf),
            ct: Some(ct),
            len,
            round_keys: Self::get_hash_round_keys(),
            _cv: PhantomData,
        }
    }

    pub fn mock(len: usize) -> Self
    where
        <E::ScalarField as FromStr>::Err: Debug,
    {
        let round_keys = Self::get_hash_round_keys();
        Self {
            attr: Some(vec![E::ScalarField::zero(); len]),
            sk_s: Some(E::ScalarField::zero()),
            nf: Some(MiMC7::<E::ScalarField>::mimc7(
                E::ScalarField::zero(),
                E::ScalarField::zero(),
                &round_keys,
            )),
            ct: Some(vec![E::G1Affine::zero(); 1]),
            len,
            round_keys,
            _cv: PhantomData,
        }
    }
}

impl<E, P> ConstraintSynthesizer<E::ScalarField> for TradeCircuit<E, P>
where
    E: Pairing,
    P: PairingVar<E, E::ScalarField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<E::ScalarField>,
    ) -> Result<(), SynthesisError> {
        let attr = Vec::<FpVar<E::ScalarField>>::new_witness(cs.clone(), || {
            self.attr.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let sk_s = FpVar::<E::ScalarField>::new_witness(cs.clone(), || {
            self.sk_s.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let nf = FpVar::<E::ScalarField>::new_input(cs.clone(), || {
            self.nf.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let ct = Vec::<P::G1Var>::new_input(cs.clone(), || {
            self.ct.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let round_keys = Vec::<FpVar<E::ScalarField>>::new_constant(cs.clone(), self.round_keys)?;

        // ============================ check nf ============================
        fn mimc7_round<E: Pairing>(
            mut msg: FpVar<E::ScalarField>,
            key: FpVar<E::ScalarField>,
            constant: &FpVar<E::ScalarField>,
        ) -> FpVar<E::ScalarField> {
            msg += key;
            msg += constant;
            let tmp = msg.clone().square().unwrap();
            let mut res = tmp.clone().square().unwrap();
            res *= tmp;
            res *= msg;
            res
        }

        let mut computed_nf = mimc7_round::<E>(attr[0].clone(), sk_s.clone(), &round_keys[0]);

        for i in 1..MIMC7_ROUNDS {
            computed_nf = mimc7_round::<E>(computed_nf, sk_s.clone(), &round_keys[i]);
        }

        computed_nf += attr[0].clone() + sk_s.clone() + sk_s;

        computed_nf.enforce_equal(&nf)?;
        // ==================================================================

        // ============================ check Enc ============================
        // let mut computed_ct = ct;
        // encryption은 뭘로 할 것인ㅏ? elgamal?
        // ===================================================================

        Ok(())
    }
}

#[cfg(test)]
mod trade_circuit {
    use super::TradeCircuit;
    use crate::utils::mimc7::*;

    use ark_bn254::{Bn254 as E, Fr as F};
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ec::pairing::Pairing;
    use ark_ed_on_bn254::EdwardsConfig as P;
    use ark_ff::PrimeField;
    use ark_groth16::{Groth16, prepare_verifying_key};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::fmt::Debug;
    use ark_std::{
        rand::{Rng, RngCore, SeedableRng},
        test_rng,
    };
    use std::convert::TryInto;
    use std::str::FromStr;

    fn test_cp_trade<E: Pairing>()
    where
        <E::ScalarField as FromStr>::Err: Debug,
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

        let attr = vec![E::ScalarField::from(2u64); LEN]; // [2, 2, ..., 2]
        let sk_s = E::ScalarField::rand(&mut rng);

        let mimc7_keys =
            MiMC7::<E::ScalarField>::round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS);

        let nf = MiMC7::<E::ScalarField>::mimc7(attr[0], sk_s, &mimc7_keys);

        // setup
        let circuit = TradeCircuit::<E, P>::mock(LEN);

        let (cc_ek, cc_vk) = CcGroth16::<E>::circuit_specific_setup(circuit, &mut rng).unwrap();
        let pvk = prepare_verifying_key::<E>(&cc_vk);
        let snark_ck = cc_ek.clone().ck;

        let mut ck = Vec::new();

        for _ in 0..LEN + 1 {
            ck.push(E::G1Affine::rand(&mut rng));
        }

        let (link_pp, link_crs) =
            LinkSnark::<E>::setup(&mut rng, LEN, ck.clone(), snark_ck, "trade");
        let (link_ek, link_vk) = LinkSnark::<E>::keygen(&mut rng, &link_pp, link_crs);

        // prove
        let o = E::ScalarField::rand(&mut rng);
        let mut cm = (ck.clone()[0] * o).into();
        for (g, a) in ck.clone().iter().skip(1).zip(attr.clone().into_iter()) {
            cm = (cm + *g * a).into();
        }

        let circuit = TradeCircuit::<E, P>::new(attr.clone(), sk_s, nf, LEN);
        let cc_prf = CcGroth16::<E>::prove(&cc_ek, circuit, &mut rng).unwrap();

        let link_witness =
            LinkSnark::<E>::generate_witness(vec![o], attr, vec![cc_prf.clone().open]);
        let (link_prf, link_cm_aux) =
            LinkSnark::<E>::prove(&mut rng, &link_pp, &link_ek, &link_witness);

        // verify
        assert!(CcGroth16::<E>::verify_proof(&pvk, &cc_prf, &[nf]).unwrap());
        let link_instance = LinkSnark::<E>::generate_instance(vec![cm], cc_prf.cm, link_cm_aux);
        // assert!(LinkSnark::<E>::verify(
        //     &link_pp,
        //     &link_vk,
        //     &link_instance,
        //     &link_prf
        // ))
    }

    #[test]
    fn test_cp_trade_bn254() {
        test_cp_trade::<E>()
    }
}
