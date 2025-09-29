use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use std::any::Any;

pub type Error = Box<dyn ark_std::error::Error>;

pub trait CCEnc<E: Pairing> {
    type Parameters: Clone;
    type PublicKey;
    type SecretKey;
    type Randomness;
    type Plaintext;
    type Ciphertext: Clone;
    type CommitKey: Clone;

    fn default_params() -> Self::Parameters;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;

    fn ck_to_box(ck: Self::CommitKey) -> Box<dyn Any>;

    fn randomness_to_box(random: Self::Randomness) -> Box<dyn Any>;

    fn plaintext_to_box(plaintext: Self::Plaintext) -> Box<dyn Any>;

    fn ciphertext_to_box(ciphertext: Self::Ciphertext) -> Box<dyn Any>;

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        aux: Box<dyn Any>,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey, Self::CommitKey), Error>;

    fn encrypt<R: Rng>(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::Randomness), Error>;

    fn decrypt(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Error>;
}
