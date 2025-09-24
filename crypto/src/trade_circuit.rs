use crate::{trade_data_structure::*, utils::mimc7::*};

use ark_ec::{AffineRepr, CurveConfig, CurveGroup, Group, pairing::Pairing};
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
pub struct TradeCircuit<C: CurveGroup, GG: CurveVar<C, C::BaseField>> {
    pub attr: Option<Vec<C::BaseField>>,
    pub sk_s: Option<C::BaseField>,
    pub nf: Option<C::BaseField>,
    pub ct: Option<CT<C>>,
    pub len: usize,
    round_keys: Vec<C::BaseField>,
    _cv: PhantomData<GG>,
}

impl<C, GG> TradeCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
{
    pub fn get_hash_round_keys() -> Vec<C::BaseField>
    where
        <C::BaseField as FromStr>::Err: Debug,
        C::BaseField: FromStr,
        C::BaseField: PrimeField,
    {
        MiMC7::<C::BaseField>::round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS)
    }

    pub fn new(
        attr: Vec<C::BaseField>,
        sk_s: C::BaseField,
        nf: C::BaseField,
        len: usize,
        ct: CT<C>,
    ) -> Self
    where
        <C::BaseField as FromStr>::Err: Debug,
        C::BaseField: FromStr,
        C::BaseField: PrimeField,
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
        <C::BaseField as FromStr>::Err: Debug,
        C::BaseField: FromStr,
        C::BaseField: PrimeField,
    {
        let round_keys = Self::get_hash_round_keys();
        Self {
            attr: Some(vec![C::BaseField::zero(); len]),
            sk_s: Some(C::BaseField::zero()),
            nf: Some(MiMC7::<C::BaseField>::mimc7(
                C::BaseField::zero(),
                C::BaseField::zero(),
                &round_keys,
            )),
            ct: Some(CT {
                ct: vec![vec![C::Affine::zero(); 2]; 1],
            }),
            len,
            round_keys,
            _cv: PhantomData,
        }
    }
}

impl<C, GG> ConstraintSynthesizer<C::BaseField> for TradeCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    C::BaseField: PrimeField,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        let attr = Vec::<FpVar<C::BaseField>>::new_witness(cs.clone(), || {
            self.attr.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let sk_s = FpVar::new_witness(cs.clone(), || {
            self.sk_s.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let nf = FpVar::new_input(cs.clone(), || {
            self.nf.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let ct = CTVar::<C, GG>::new_input(cs.clone(), || {
            self.ct.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let round_keys = Vec::<FpVar<C::BaseField>>::new_constant(cs.clone(), self.round_keys)?;

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

        let mut computed_nf =
            mimc7_round::<C::BaseField>(attr[0].clone(), sk_s.clone(), &round_keys[0]);

        for i in 1..MIMC7_ROUNDS {
            computed_nf = mimc7_round::<C::BaseField>(computed_nf, sk_s.clone(), &round_keys[i]);
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
    use ark_ec::CurveGroup;
    use ark_ec::pairing::Pairing;
    use ark_ed_on_bn254::{EdwardsProjective as C, constraints::EdwardsVar as GG};
    use ark_ff::PrimeField;
    use ark_groth16::{Groth16, prepare_verifying_key};
    use ark_r1cs_std::groups::CurveVar;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::fmt::Debug;
    use ark_std::{
        rand::{Rng, RngCore, SeedableRng},
        test_rng,
    };
    use std::convert::TryInto;
    use std::str::FromStr;

    #[test]
    fn test_cp_trade()
    // fn test_cp_trade<E: Pairing, C: CurveGroup, GG: CurveVar<C, C::BaseField>>()
    // where
    //     <E::ScalarField as FromStr>::Err: Debug,
    //     <C::BaseField as FromStr>::Err: Debug,
    //     <C as ark_ec::CurveGroup>::BaseField: ark_ff::PrimeField,
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
        let sk_s = F::rand(&mut rng);

        let mimc7_keys = MiMC7::<F>::round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS);

        let nf = MiMC7::<F>::mimc7(attr[0], sk_s, &mimc7_keys);

        // setup
        let circuit = TradeCircuit::<C, GG>::mock(LEN);

        let (cc_ek, cc_vk) = CcGroth16::<E>::circuit_specific_setup(circuit, &mut rng).unwrap();
        let pvk = prepare_verifying_key::<E>(&cc_vk);
        let snark_ck = cc_ek.clone().ck;

        let mut ck = Vec::new();

        for _ in 0..LEN + 1 {
            ck.push(ark_bn254::G1Affine::rand(&mut rng));
        }

        let (link_pp, link_crs) =
            LinkSnark::<E>::setup(&mut rng, LEN, ck.clone(), snark_ck, "trade");
        let (link_ek, link_vk) = LinkSnark::<E>::keygen(&mut rng, &link_pp, link_crs);

        // prove
        let o = F::rand(&mut rng);
        let mut cm_prj = ck.clone()[0] * o;
        for (g, a) in ck.clone().iter().skip(1).zip(attr.clone().into_iter()) {
            cm_prj = cm_prj + *g * a;
        }
        let cm = cm_prj.into();

        let circuit = TradeCircuit::<C, GG>::new(attr.clone(), sk_s, nf, ct, LEN);
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
}
