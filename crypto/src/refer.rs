#![allow(dead_code)]
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use hex::{self, decode, encode};
use serde::{
    de::{Error as DeError, SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserializer, Serializer,
};
use std::marker::PhantomData;

/// CanonicalSerialize를 구현하는 타입을 직렬화하는 함수
pub(super) fn serialize<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: CanonicalSerialize,
{
    let mut buffer = Vec::new();
    value
        .serialize_compressed(&mut buffer)
        .map_err(serde::ser::Error::custom)?;
    let encoded = encode(&buffer);
    serializer.serialize_str(&encoded)
}

/// CanonicalDeserialize를 구현하는 타입을 역직렬화하는 함수
pub(super) fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: CanonicalDeserialize,
{
    struct StringVisitor<T> {
        marker: PhantomData<T>,
    }

    impl<'de, T: CanonicalDeserialize> Visitor<'de> for StringVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string")
        }

        fn visit_str<E>(self, value: &str) -> Result<T, E>
        where
            E: DeError,
        {
            let decoded = decode(value).map_err(E::custom)?;
            T::deserialize_compressed_unchecked(&*decoded).map_err(E::custom)
        }
    }

    deserializer.deserialize_str(StringVisitor {
        marker: PhantomData,
    })
}
/// Vector타입으로 들어오는 변수들의 CanonicalSerialize를 구현하는 타입을
/// 직렬화하는 함수
pub fn serialize_vec<T, S>(vec: &Vec<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    T: CanonicalSerialize,
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(vec.len()))?;
    for element in vec {
        let mut buffer = Vec::new();
        element
            .serialize_compressed(&mut buffer)
            .map_err(serde::ser::Error::custom)?;
        let encoded = encode(&buffer);
        seq.serialize_element(&encoded)?;
    }
    seq.end()
}

/// Vector타입으로 들어오는 변수들의 CanonicalDeserialize를 구현하는 타입을
/// 역직렬화하는 함수
pub fn deserialize_vec<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    T: CanonicalDeserialize,
    D: Deserializer<'de>,
{
    struct VecVisitor<T> {
        marker: PhantomData<T>,
    }

    impl<'de, T> Visitor<'de> for VecVisitor<T>
    where
        T: CanonicalDeserialize,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a sequence of base64 encoded strings")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(encoded) = seq.next_element::<String>()? {
                let decoded = decode(&encoded).map_err(DeError::custom)?;
                let element =
                    T::deserialize_compressed_unchecked(&*decoded).map_err(DeError::custom)?;
                vec.push(element);
            }
            Ok(vec)
        }
    }

    deserializer.deserialize_seq(VecVisitor {
        marker: PhantomData,
    })
}