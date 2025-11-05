use crate::encryption::cc_enc::{CCEnc, Error};
use ark_ec::{CurveGroup, pairing::Pairing};
use ark_ff::{UniformRand, fields::PrimeField};
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_std::marker::PhantomData;
use ark_std::ops::Mul;
use ark_std::rand::Rng;
use std::any::Any;

#[derive(Clone, Default, Debug, PartialEq)]
pub struct ElGamal<E: Pairing> {
    _group: PhantomData<E>,
}

#[derive(Clone, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters<E: Pairing> {
    pub generator: E::G1Affine,
}

impl<E: Pairing> Default for Parameters<E> {
    fn default() -> Self {
        Self {
            generator: E::G1Affine::default(),
        }
    }
}

#[derive(Clone, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ElGamalCommitKey<E: Pairing> {
    pub ck: Vec<E::G1Affine>, // length
}

impl<E: Pairing> Default for ElGamalCommitKey<E> {
    fn default() -> Self {
        Self { ck: Vec::new() }
    }
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey<E: Pairing> {
    pub pk: Vec<E::G1Affine>,
}

impl<E: Pairing> Default for PublicKey<E> {
    fn default() -> Self {
        Self { pk: Vec::new() }
    }
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey<E: Pairing> {
    pub sk: E::ScalarField,
}

impl<E: Pairing> Default for SecretKey<E> {
    fn default() -> Self {
        Self {
            sk: E::ScalarField::default(),
        }
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Randomness<E: Pairing> {
    pub randness: Vec<E::ScalarField>,
}

impl<E: Pairing> Randomness<E> {
    pub fn from_randomness_vec(random_vec: Vec<E::ScalarField>) -> Self {
        Self {
            randness: random_vec,
        }
    }
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Ciphertext<E: Pairing> {
    pub ct: Vec<Vec<E::G1Affine>>,
}

impl<E: Pairing> Ciphertext<E> {
    pub fn from_ciphertext_vec(ct_vec: Vec<Vec<E::G1Affine>>) -> Self {
        Self { ct: ct_vec }
    }
}

impl<E: Pairing> Default for Ciphertext<E> {
    fn default() -> Self {
        Self { ct: Vec::default() }
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Plaintext<E: Pairing> {
    pub msg: Vec<E::ScalarField>,
}

impl<E: Pairing> Plaintext<E> {
    pub fn from_plaintext_vec(pt_vec: Vec<E::ScalarField>) -> Self {
        Self { msg: pt_vec }
    }
}

// Message bit is less than 8bit
impl<E: Pairing> CCEnc<E> for ElGamal<E> {
    type PublicKey = PublicKey<E>;
    type SecretKey = SecretKey<E>;
    type Randomness = Randomness<E>;
    type Parameters = Parameters<E>;
    type Ciphertext = Ciphertext<E>;
    type Plaintext = Plaintext<E>;
    type CommitKey = ElGamalCommitKey<E>;

    fn default_params() -> Self::Parameters {
        Self::Parameters::default()
    }

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        let generator = E::G1Affine::rand(rng).into();

        Ok(Parameters { generator })
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        aux: Box<(dyn Any + 'static)>,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey, Self::CommitKey), Error> {
        let sk = E::ScalarField::rand(rng);
        let h = pp.generator * sk;
        let pk = [pp.generator, h.into_affine()].to_vec();
        let ck = [h.into_affine(), pp.generator].to_vec();

        Ok((
            PublicKey { pk: pk.into() },
            SecretKey { sk: sk.into() },
            ElGamalCommitKey { ck: ck.into() },
        ))
    }

    fn encrypt<R: Rng>(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        msg: &Self::Plaintext,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::Randomness), Error> {
        let mut ct_vec: Vec<Vec<E::G1Affine>> = Vec::new();
        let mut r_vec: Vec<E::ScalarField> = Vec::new();

        for (idx, m) in msg.msg.iter().enumerate() {
            let r: E::ScalarField = E::ScalarField::rand(rng);
            let ct_0 = pp.generator * r;
            let ct_1 = pk.pk[1] * r + pp.generator * m;
            ct_vec.push([ct_0.into_affine(), ct_1.into_affine()].to_vec());
            r_vec.push(r);
        }

        Ok((
            Ciphertext { ct: ct_vec.into() },
            Randomness {
                randness: r_vec.into(),
            },
        ))
    }

    fn decrypt(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, Error> {
        let mut msg_vec = Vec::new();
        for (idx, ct) in ciphertext.ct.iter().enumerate() {
            let ct0: E::G1Affine = ct[0];
            let ct1: E::G1Affine = ct[1];
            let res = ct1 + -(ct0 * sk.sk);
            for i in 0..=u64::MAX {
                // |M| = 64 bit
                let fr_i = E::ScalarField::from_bigint((i as u64).into()).unwrap();
                if pp.generator.mul(fr_i).eq(&res) == true {
                    msg_vec.push(fr_i);
                    break;
                }
            }
        }
        Ok(Plaintext {
            msg: msg_vec.into(),
        })
    }

    fn ck_to_box(ck: Self::CommitKey) -> Box<dyn Any> {
        Box::new(ck)
    }

    fn randomness_to_box(random: Self::Randomness) -> Box<dyn Any> {
        Box::new(random)
    }

    fn plaintext_to_box(plaintext: Self::Plaintext) -> Box<dyn Any> {
        Box::new(plaintext)
    }

    fn ciphertext_to_box(ciphertext: Self::Ciphertext) -> Box<dyn Any> {
        Box::new(ciphertext)
    }
}
