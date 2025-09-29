pub mod cc_enc;
pub mod encryption;
pub mod trade_circuit;
pub mod trade_constraints;
use crate::encryption::{cc_enc::CCEnc, trade_circuit::TradeCircuit};

use ark_crypto_primitives::snark::FromFieldElementsGadget;
use ark_ec::pairing::Pairing;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};

use ark_ff::fields::PrimeField;
pub trait CCEncGadget<E: Pairing, C: CCEnc<E>, ConstraintF: PrimeField> {
    type ParametersVar: AllocVar<C::Parameters, ConstraintF> + Clone;
    type PlaintextVar: AllocVar<Vec<E::ScalarField>, ConstraintF>
        + FromFieldElementsGadget<E::ScalarField, ConstraintF>
        + Clone;
    type PublicKeyVar: AllocVar<C::PublicKey, ConstraintF> + Clone;
    type RandomnessVar: AllocVar<Vec<E::ScalarField>, ConstraintF>
        + FromFieldElementsGadget<E::ScalarField, ConstraintF>
        + Clone;
    type CiphertextVar: AllocVar<C::Ciphertext, ConstraintF> + Clone;

    fn encrypt(
        parameters: &Self::ParametersVar,
        message: &Self::PlaintextVar,
        randomness: &Self::RandomnessVar,
        public_key: &Self::PublicKeyVar,
        ciphertext: &Self::CiphertextVar,
    ) -> Result<Vec<Boolean<ConstraintF>>, SynthesisError>;
}
