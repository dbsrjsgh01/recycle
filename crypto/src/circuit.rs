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
pub struct Circuit<F: PrimeField> {
    pub attr: Option<Vec<F>>,
    pub cond: Option<Vec<F>>,
    pub chk1: Option<Vec<bool>>,
    pub len: usize,
}

impl<F: PrimeField> Circuit<F> {
    pub fn new(attr: Vec<F>, cond: Vec<F>, chk1: Vec<bool>, len: usize) -> Self {
        Self {
            attr: Some(attr),
            cond: Some(cond),
            chk1: Some(chk1),
            len,
        }
    }

    pub fn mock(len: usize) -> Self {
        Self {
            attr: Some(vec![F::zero(); len]),
            cond: Some(vec![F::zero(); len]),
            chk1: Some(vec![false; len]),
            len,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Circuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let attr = Vec::<FpVar<F>>::new_witness(cs.clone(), || {
            self.attr.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let cond = Vec::<FpVar<F>>::new_input(cs.clone(), || {
            self.cond.ok_or(SynthesisError::AssignmentMissing)
        })?;

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
mod circuit {
    use super::Circuit;
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
    fn test_circuit() {
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

        let circuit = Circuit::<F>::new(attr, cond.clone(), chk1, LEN);

        // number of constraints
        let cs = ark_relations::r1cs::ConstraintSystem::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        println!("Num of constraints: {:#?}", cs.num_constraints());

        let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

        let pvk = prepare_verifying_key::<E>(&vk);

        let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &vec_to_arr(cond), &proof).unwrap());
    }
}
