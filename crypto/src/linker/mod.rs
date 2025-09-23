pub mod matrix;
pub mod relation_generator;
pub mod snark;

use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;

pub trait Linker<E: Pairing> {
    type CRS;
    type Witness;
    type Instance;

    type PP: Clone;
    type EK: Clone;
    type VK: Clone;

    type CM: Clone + Copy;
    type Proof: Clone;

    fn setup<R: Rng>(
        rng: &mut R,
        num: usize,
        ck: Vec<E::G1Affine>,
        snark_ck: Vec<E::G1Affine>,
        mode: &str,
    ) -> (Self::PP, Self::CRS);

    fn keygen<R: Rng>(rng: &mut R, pp: &Self::PP, crs: Self::CRS) -> (Self::EK, Self::VK);

    fn prove<R: Rng>(
        rng: &mut R,
        pp: &Self::PP,
        ek: &Self::EK,
        witness: &Self::Witness,
    ) -> (Self::Proof, Self::CM);

    fn verify(pp: &Self::PP, vk: &Self::VK, instance: &Self::Instance, proof: &Self::Proof)
    -> bool;

    fn generate_witness(
        r: Vec<E::ScalarField>,
        witness: Vec<E::ScalarField>,
        snark_witness: Vec<E::ScalarField>,
    ) -> Self::Witness;

    fn generate_instance(
        cm: Vec<E::G1Affine>,
        snark_cm: E::G1Affine,
        aux_cm: Self::CM,
    ) -> Self::Instance;
}
