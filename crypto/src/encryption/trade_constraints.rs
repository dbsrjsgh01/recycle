use crate::encryption::{
    CCEncGadget,
    encryption::{Ciphertext, ElGamal, Parameters, PublicKey},
};
use ark_crypto_primitives::snark::BooleanInputVar;
use ark_ec::{CurveGroup, pairing::Pairing};
use ark_ff::fields::Field;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::boolean::Boolean,
    eq::EqGadget,
    pairing::PairingVar,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{borrow::Borrow, marker::PhantomData, vec::Vec};

pub(crate) type BasePrimeField<E> =
    <<<E as Pairing>::G1 as CurveGroup>::BaseField as Field>::BasePrimeField;

#[derive(Derivative)]
#[derivative(Clone(bound = "P::G1Var: Clone"))]
pub struct ParametersVar<E: Pairing, P: PairingVar<E, BasePrimeField<E>>> {
    pub generator: P::G1Var,
    _pairing: PhantomData<P>,
}

impl<E, P> AllocVar<Parameters<E>, BasePrimeField<E>> for ParametersVar<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    fn new_variable<T: Borrow<Parameters<E>>>(
        cs: impl Into<Namespace<BasePrimeField<E>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|param| {
            let Parameters { generator } = param.borrow().clone();
            let generator = P::G1Var::new_variable(
                ark_relations::ns!(cs, "generator"),
                || Ok(generator),
                mode,
            )?;
            Ok(Self {
                generator,
                _pairing: PhantomData,
            })
        })
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "P::G1Var: Clone"))]
pub struct PublicKeyVar<E: Pairing, P: PairingVar<E, BasePrimeField<E>>> {
    pub pk: Vec<P::G1Var>,
}

impl<E, P> AllocVar<PublicKey<E>, BasePrimeField<E>> for PublicKeyVar<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    fn new_variable<T: Borrow<PublicKey<E>>>(
        cs: impl Into<Namespace<BasePrimeField<E>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|pk| {
            let PublicKey { pk } = pk.borrow().clone();
            let pk = Vec::new_variable(ark_relations::ns!(cs, "pk"), || Ok(pk), mode)?;
            Ok(Self { pk })
        })
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "P::G1Var: Clone"))]
pub struct CiphertextVar<E: Pairing, P: PairingVar<E, BasePrimeField<E>>> {
    pub ct_0: Vec<P::G1Var>,
    pub ct_1: Vec<P::G1Var>,
}

impl<E, P> AllocVar<Ciphertext<E>, BasePrimeField<E>> for CiphertextVar<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    fn new_variable<T: Borrow<Ciphertext<E>>>(
        cs: impl Into<Namespace<BasePrimeField<E>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|ct| {
            let ct = ct.borrow();
            let (ct_0, ct_1) = ct.clone().ct.into_iter().fold(
                (Vec::new(), Vec::new()),
                |(mut left, mut right), v| {
                    left.push(v[0]);
                    right.push(v[1]);
                    (left, right)
                },
            );
            let ct_0 = Vec::new_variable(ark_relations::ns!(cs, "ct_0"), || Ok(ct_0), mode)?;
            let ct_1 = Vec::new_variable(ark_relations::ns!(cs, "ct_1"), || Ok(ct_1), mode)?;

            Ok(CiphertextVar { ct_0, ct_1 })
        })
    }
}

pub struct ElGamalEncGadget<E: Pairing, P: PairingVar<E, BasePrimeField<E>>> {
    _pairing_engine: PhantomData<E>,
    _pairing_gadget: PhantomData<P>,
}

impl<E, P> CCEncGadget<E, ElGamal<E>, BasePrimeField<E>> for ElGamalEncGadget<E, P>
where
    E: Pairing,
    P: PairingVar<E, BasePrimeField<E>>,
{
    type ParametersVar = ParametersVar<E, P>;
    type PlaintextVar = BooleanInputVar<E::ScalarField, BasePrimeField<E>>;
    type PublicKeyVar = PublicKeyVar<E, P>;
    type RandomnessVar = BooleanInputVar<E::ScalarField, BasePrimeField<E>>;
    type CiphertextVar = CiphertextVar<E, P>;

    fn encrypt(
        parameters: &Self::ParametersVar,
        message: &Self::PlaintextVar,
        randomness: &Self::RandomnessVar,
        public_key: &Self::PublicKeyVar,
        ciphertext: &Self::CiphertextVar,
    ) -> Result<Vec<Boolean<BasePrimeField<E>>>, SynthesisError> {
        let generator = parameters.generator.clone();

        let mut circuit_msg = message.clone().into_iter();
        let mut circuit_randomness = randomness.clone().into_iter();
        let mut circuit_pk = public_key.pk.clone();

        let circuit_ct_0 = ciphertext.ct_0.clone();
        let circuit_ct_1 = ciphertext.ct_1.clone();

        let mut verify_vec: Vec<Boolean<BasePrimeField<E>>> = Vec::new();

        let g = generator;
        let mut len = 0;

        for (m, r) in circuit_msg
            .by_ref()
            .zip(circuit_randomness.by_ref().into_iter())
        {
            let ct_0: P::G1Var = g.scalar_mul_le(r.to_bits_le()?.iter())?;
            let ct_1: P::G1Var = circuit_pk[1].scalar_mul_le(r.to_bits_le()?.iter())?
                + g.scalar_mul_le(m.to_bits_le()?.iter())?;

            ct_0.is_eq(&circuit_ct_0[len])
                .unwrap()
                .enforce_equal(&Boolean::constant(true))
                .unwrap();
            ct_1.is_eq(&circuit_ct_1[len])
                .unwrap()
                .enforce_equal(&Boolean::constant(true))
                .unwrap();

            verify_vec.push(ct_0.is_eq(&circuit_ct_0[len])?);
            verify_vec.push(ct_1.is_eq(&circuit_ct_1[len])?);
            len += 1;
        }
        assert_eq!(len, circuit_ct_0.len());

        Ok(verify_vec)
    }
}

#[cfg(test)]
mod tests {
    use crate::encryption::CCEncGadget;
    use crate::encryption::{
        cc_enc::CCEnc,
        encryption::{ElGamal, Plaintext, Randomness},
        trade_constraints::ElGamalEncGadget,
    };
    use ark_ec::pairing::Pairing;
    use ark_ff::{BigInteger, BigInteger256};
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::Rng;
    use ark_std::{UniformRand, test_rng};

    #[test]
    fn test_elgamal_gadget_bls12_381() {
        use ark_bls12_381::{Bls12_381, Config, Fq, Fr};
        let mut rng = &mut test_rng();

        type PairingVar = ark_r1cs_std::pairing::bls12::PairingVar<Config>;
        type CCEnc = ElGamal<Bls12_381>;
        type MyElGamalGadget = ElGamalEncGadget<Bls12_381, PairingVar>;

        // compute primitive result
        let pp = CCEnc::setup(rng).unwrap();
        let (pk, sk, _) = CCEnc::keygen(&pp, Box::new(32), rng).unwrap();
        let message: BigInteger256 = BigInteger256::rand(rng);
        let u8_bytes_be = message.to_bytes_be();
        let msg_vec: Vec<Fr> = u8_bytes_be.iter().map(|&byte| Fr::from(byte)).collect();
        let plaintext = Plaintext::<Bls12_381> {
            msg: msg_vec.clone(),
        };
        let (ct, randomness) = CCEnc::encrypt(&pp, &pk, &plaintext, &mut rng).unwrap();

        let random = randomness.randness.as_slice();
        let randomness_fr: Vec<Fr> = random.iter().map(|&f| Fr::from(f)).collect();

        let plaintext_fr: Vec<Fr> = plaintext.msg.iter().map(|&f| Fr::from(f)).collect();

        // construct constraint system
        let cs = ConstraintSystem::<Fq>::new_ref();
        let parameters_var = <MyElGamalGadget as CCEncGadget<
            Bls12_381,
            CCEnc,
            <Bls12_381 as Pairing>::BaseField,
        >>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "gadget_parameters"), &pp
        )
        .unwrap();

        let publickey_var = <MyElGamalGadget as CCEncGadget<
            Bls12_381,
            CCEnc,
            <Bls12_381 as Pairing>::BaseField,
        >>::PublicKeyVar::new_witness(
            ark_relations::ns!(cs, "gadget_publickey"), || Ok(pk)
        )
        .unwrap();

        let randomness_var = <MyElGamalGadget as CCEncGadget<
            Bls12_381,
            CCEnc,
            <Bls12_381 as Pairing>::BaseField,
        >>::RandomnessVar::new_witness(
            ark_relations::ns!(cs, "gadget_randomness"),
            || Ok(randomness_fr),
        )
        .unwrap();

        let ciphertext_var = <MyElGamalGadget as CCEncGadget<
            Bls12_381,
            CCEnc,
            <Bls12_381 as Pairing>::BaseField,
        >>::CiphertextVar::new_input(
            ark_relations::ns!(cs, "gadget_ciphertext"), || Ok(ct)
        )
        .unwrap();

        let plaintext_var = <MyElGamalGadget as CCEncGadget<
            Bls12_381,
            CCEnc,
            <Bls12_381 as Pairing>::BaseField,
        >>::PlaintextVar::new_witness(
            ark_relations::ns!(cs, "gadget_plaintext"),
            || Ok(plaintext_fr),
        )
        .unwrap();

        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints not satisfied: {}",
            cs.which_is_unsatisfied().unwrap().unwrap_or_default()
        );

        MyElGamalGadget::encrypt(
            &parameters_var,
            &plaintext_var,
            &randomness_var,
            &publickey_var,
            &ciphertext_var,
        )
        .unwrap();

        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints not satisfied: {}",
            cs.which_is_unsatisfied().unwrap().unwrap_or_default()
        );

        println!("CS :: [{}]", cs.num_constraints());
    }
}
