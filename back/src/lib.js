import ffi from "ffi-napi";
import ref from "ref-napi";

const boolArray = ref.refType("bool");
const frArray = ref.refType("uint64");

const lib = ffi.Library("../crypto/target/release/libtest_circuit.dylib", {
    // setup_dpp_bn254(param_path, Length, cond) -> bool
    setup_dpp_bn254: ["bool", ["string", "int", frArray]],
    // prove_dpp_bn254(param_path, attr, cond, chk, Length) -> bool
    prove_dpp_bn254: ["bool", ["string", frArray, frArray, boolArray, "int"]],
    // verify_dpp_bn254(param_path, cond, Length) -> bool
    verify_dpp_bn254: ["bool", ["string", frArray, "int"]],

    // setup_trade_bn254(param_path, Length, nf) -> bool
    setup_trade_bn254: ["bool", ["string", "int", frArray]],
    // prove_trade_bn254(param_path, attr, sk_s, cm_old, nf, Length) -> bool
    prove_trade_bn254: [
        "bool",
        ["string", frArray, frArray, frArray, frArray, "int"],
    ],
    // verify_trade_bn254(param_path, Length) -> bool
    verify_trade_bn254: ["bool", ["string", "int"]],

    // get_*_bn254(param_path, boolean) -> string (true => values related to trade / false => values related to dpp)
    get_cc_vk_bn254: ["string", ["string", "bool"]],
    get_cc_proof_bn254: ["string", ["string", "bool"]],
    get_link_vk_bn254: ["string", ["string", "bool"]],
    get_link_proof_bn254: ["string", ["string", "bool"]],

    // mimc7_bn254(left, right) -> [u64; 4] : mimc7 hash function
    get_nf: ["void", [frArray, frArray, frArray]],
});

export default lib;
