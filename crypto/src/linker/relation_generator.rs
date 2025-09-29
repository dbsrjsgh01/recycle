use crate::linker::{
    matrix::SparseMatrix,
    snark::{LinkSnark, PP},
};

use ark_ec::pairing::Pairing;
use ark_relations::r1cs::SynthesisError;

use super::Linker;

pub fn generate_cp_dpp_relation<E: Pairing>(
    msg_len: usize,
    ck: Vec<E::G1Affine>,
    snark_ck: Vec<E::G1Affine>,
) -> SparseMatrix<E::G1Affine> {
    let l = 2;
    let t = msg_len + 2;

    let mut snark_ck = snark_ck.clone();
    snark_ck.truncate(msg_len + 1);

    let mut crs = SparseMatrix::new(l, t);

    // cm_attr
    crs.insert_row_slice(0, 0, &vec![ck[0]]);
    for i in 0..msg_len {
        crs.insert_row_slice(0, i + 2, &vec![ck[i + 1]]);
    }

    // snark_ck
    crs.insert_row_slice(l - 1, 1, &snark_ck);

    crs
}

// 보일 것: ct, cm, snark_cm 모두 같은 attr 사용함
// 근데 여기서 추가로 들어가는 것: ct는 r, cm은 o, snark_cm은 delta => 랜덤값 받을 앞부분을 세 칸 정도 비워놔야함
// 그래서 사이즈는 3 * (len + 3) 정도로 추정; 확실하게 다시 확인할 것
pub fn generate_cp_trade_relation<E: Pairing>(
    msg_len: usize,
    ck: Vec<E::G1Affine>,
    snark_ck: Vec<E::G1Affine>,
) -> SparseMatrix<E::G1Affine> {
    let l = 2 * msg_len + 1; // 2l + 1
    let t = 2 * msg_len + 1; // 2l + 2, since 'ONE' is contained
    let mut crs = SparseMatrix::new(l, t);

    for i in 0..msg_len {
        crs.insert_row_slice(2 * i, i, &vec![ck[1]]); // ct_0 part
        crs.insert_row_slice(2 * i + 1, i, &vec![ck[0]]); // ct_1 part
        crs.insert_row_slice(2 * i + 1, i + msg_len + 1, &vec![ck[1]]);
        // ct_1 part
    }
    assert_eq!(snark_ck.len(), msg_len + 1);
    crs.insert_row_slice(l - 1, msg_len, &snark_ck.to_vec());

    crs
}

pub fn generate_cp_witness<E: Pairing>(
    r: Vec<E::ScalarField>,
    u: Vec<E::ScalarField>,
    snark_witness: Vec<E::ScalarField>,
) -> Result<<LinkSnark<E> as Linker<E>>::Witness, SynthesisError> {
    let mut witness_vec = Vec::new();
    witness_vec.extend_from_slice(r.as_slice());
    witness_vec.extend_from_slice(snark_witness.as_slice());
    witness_vec.extend_from_slice(u.as_slice());

    Ok(witness_vec)
}

pub fn generate_cp_instance<E: Pairing>(
    cm: Vec<E::G1Affine>,
    snark_cm: E::G1Affine,
) -> Result<<LinkSnark<E> as Linker<E>>::Instance, SynthesisError> {
    let mut instance_vec = cm;

    instance_vec.push(snark_cm);

    Ok(instance_vec)
}
