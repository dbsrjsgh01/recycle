use crate::ConstraintF;

use ark_ec::CurveGroup;
use ark_ff::{
    One, PrimeField,
    biginteger::{BigInteger as _, BigInteger64 as B},
};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, prelude::*, uint32::UInt32};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, SynthesisMode},
};
use std::{
    cmp,
    marker::PhantomData,
    ops::{AddAssign, Mul, MulAssign, Not},
};

#[derive(Clone, Debug)]
pub struct DPPCircuit<F: PrimeField> {
    pub attr: Option<Vec<F>>,
    pub cond: Option<Vec<F>>,
    pub chk1: Option<Vec<bool>>,
    pub len: usize,
}

impl<F: PrimeField> DPPCircuit<F> {
    pub fn new(attr: Vec<F>, cond: Vec<F>, chk1: Vec<bool>, len: usize) -> Self {
        Self {
            attr: Some(attr),
            cond: Some(cond),
            chk1: Some(chk1),
            len,
        }
    }

    pub fn mock(len: usize, cond: Vec<F>) -> Self {
        Self {
            attr: Some(vec![F::zero(); len]),
            cond: Some(cond),
            chk1: Some(vec![false; len]),
            len,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DPPCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let attr = Vec::<FpVar<F>>::new_input(cs.clone(), || {
            self.attr.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let cond = Vec::<FpVar<F>>::new_constant(cs.clone(), self.cond.unwrap())?;

        let chk1 = Vec::<Boolean<F>>::new_witness(cs.clone(), || {
            self.chk1.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let one = FpVar::<F>::new_constant(cs.clone(), F::one())?;
        let zero = FpVar::<F>::new_constant(cs.clone(), F::zero())?;

        // 한 cycle 당 약 2000개: 약 14~15 ms
        for i in 0..self.len {
            let mut res = chk1[i]
                .clone()
                .not()
                .or(&chk1[i]
                    .and(
                        &attr[i]
                            .is_cmp(&cond[i], cmp::Ordering::Greater, false)
                            .unwrap(),
                    )
                    .unwrap())
                .unwrap();
            res.enforce_equal(&Boolean::TRUE)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod dpp_circuit {
    use super::DPPCircuit;
    use ark_bn254::{Bn254 as E, Fr as F};
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_groth16::{Groth16, prepare_verifying_key};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_std::{
        rand::{Rng, RngCore, SeedableRng},
        test_rng,
    };
    use std::convert::TryInto;

    #[test]
    fn test_dpp_circuit() {
        const LEN: usize = 50;

        fn vec_to_arr<T>(v: Vec<T>) -> [T; LEN] {
            v.try_into()
                .unwrap_or_else(|v: Vec<T>| panic!("Cannot convert into an array"))
        }

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let attr = vec![F::from(2u64); LEN]; // [2, 2, ..., 2]

        let cond = vec![F::from(1u64); LEN]; // [1, 1, ..., 1]

        let mut chk1 = vec![true; LEN / 2]; // [1, 1, ..., 1]
        chk1.extend_from_slice(&[false; LEN / 2]); // [0, 0, ..., 0]

        let circuit = DPPCircuit::<F>::new(attr.clone(), cond.clone(), chk1, LEN);

        // number of constraints
        let cs = ark_relations::r1cs::ConstraintSystem::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        println!("Num of constraints: {:#?}", cs.num_constraints());

        let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

        let pvk = prepare_verifying_key::<E>(&vk);

        let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &vec_to_arr(attr), &proof).unwrap());
    }

    use ark_ec::pairing::Pairing;
    use ark_ff::PrimeField;
    fn test_cp_dpp<E: Pairing>() {
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

        let cond = vec![E::ScalarField::from(1u64); LEN]; // [1, 1, ..., 1]

        let mut chk1 = vec![true; LEN / 2]; // [1, 1, ..., 1]
        chk1.extend_from_slice(&[false; LEN / 2]); // [0, 0, ..., 0]

        // setup
        let circuit = DPPCircuit::<E::ScalarField>::mock(LEN, cond.clone());

        let (cc_ek, cc_vk) = CcGroth16::<E>::circuit_specific_setup(circuit, &mut rng).unwrap();
        let pvk = prepare_verifying_key::<E>(&cc_vk);
        let snark_ck = cc_ek.clone().ck;

        let mut ck = Vec::new();

        for _ in 0..LEN + 1 {
            ck.push(E::G1Affine::rand(&mut rng));
        }

        let (link_pp, link_crs) = LinkSnark::<E>::setup(&mut rng, LEN, ck.clone(), snark_ck, "dpp");
        let (link_ek, link_vk) = LinkSnark::<E>::keygen(&mut rng, &link_pp, link_crs);

        // prove
        let o = E::ScalarField::rand(&mut rng);
        let mut cm = (ck.clone()[0] * o).into();
        // for (g, a) in ck.clone().iter().skip(1).zip(attr.clone().into_iter()) {
        for (g, a) in ck.clone().iter().skip(1).zip(attr.clone().into_iter()) {
            cm = (cm + *g * a).into();
        }

        let circuit = DPPCircuit::<E::ScalarField>::new(attr.clone(), cond.clone(), chk1, LEN);
        let cc_prf = CcGroth16::<E>::prove(&cc_ek, circuit, &mut rng).unwrap();

        let link_witness =
            LinkSnark::<E>::generate_witness(vec![o], attr.clone(), vec![cc_prf.clone().open]);
        // LinkSnark::<E>::generate_witness(vec![o], attr, vec![cc_prf.clone().open]);
        let (link_prf, link_cm_aux) =
            LinkSnark::<E>::prove(&mut rng, &link_pp, &link_ek, &link_witness);

        // test
        use ark_ec::{AffineRepr, VariableBaseMSM};
        let instance_assignment = attr.iter().map(|s| s.into_bigint()).collect::<Vec<_>>();
        let mut computed_cm = E::G1::msm_bigint(&cc_ek.vk.gamma_abc_g1[1..], &instance_assignment);
        computed_cm = computed_cm + cc_ek.vk.eta_gamma_inv_g1.into_group() * cc_prf.open;
        assert_eq!(computed_cm, cc_prf.cm.into(), "Computation Error");

        // verify
        assert!(CcGroth16::<E>::verify_proof(&pvk, &cc_prf, &vec_to_arr(attr)).unwrap());
        let link_instance = LinkSnark::<E>::generate_instance(vec![cm], cc_prf.cm, link_cm_aux);
        assert!(LinkSnark::<E>::verify(
            &link_pp,
            &link_vk,
            &link_instance,
            &link_prf
        ))
    }

    #[test]
    fn test_cp_dpp_bn254() {
        test_cp_dpp::<E>()
    }
}
