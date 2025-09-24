use crate::{BasePrimeField, utils::mimc7::*};

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
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError, SynthesisMode},
};
use ark_std::{UniformRand, Zero, fmt::Debug};
use rand::Rng;
use std::{
    borrow::Borrow,
    cmp,
    marker::PhantomData,
    ops::{AddAssign, Mul, MulAssign, Not},
    str::FromStr,
};

#[derive(Clone, Debug)]
pub struct PP<C: CurveGroup> {
    pub g: C::Affine,
    pub h: C::Affine,
}

#[derive(Clone, Debug)]
pub struct CT<C: CurveGroup> {
    pub ct: Vec<Vec<C::Affine>>,
}

pub struct ElGamal<C: CurveGroup> {
    _curve: PhantomData<C>,
}

impl<C: CurveGroup> ElGamal<C> {
    pub fn encrypt<R: Rng>(
        pp: PP<C>,
        pt: Vec<C::BaseField>,
        rng: &mut R,
    ) -> (Vec<C::BaseField>, CT<C>) {
        let mut rand: Vec<C::BaseField> = Vec::new();
        let mut ct: Vec<Vec<C::Affine>> = Vec::new();

        for pt_i in pt.clone().iter() {
            let r = C::BaseField::rand(rng);
            rand.push(r);
            let ct_0 = pp.clone().g.mul(r).into();
        }

        (rand, CT::<C> { ct })
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "GG: Clone"))]
pub struct PPVar<C: CurveGroup, GG: CurveVar<C, C::BaseField>> {
    pub g: GG,
    pub h: GG,
    _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<PP<C>, C::BaseField> for PPVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<PP<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|param| {
            let PP { g, h } = param.borrow().clone();
            let g = GG::new_variable(ark_relations::ns!(cs, "generator"), || Ok(g), mode)?;
            let h = GG::new_variable(ark_relations::ns!(cs, "pk"), || Ok(h), mode)?;

            Ok(Self {
                g,
                h,
                _curve: PhantomData,
            })
        })
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "GG: Clone"))]
pub struct CTVar<C: CurveGroup, GG: CurveVar<C, C::BaseField>> {
    pub ct_0: Vec<GG>,
    pub ct_1: Vec<GG>,
    _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<CT<C>, C::BaseField> for CTVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<CT<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
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

            Ok(CTVar {
                ct_0,
                ct_1,
                _curve: PhantomData,
            })
        })
    }
}
