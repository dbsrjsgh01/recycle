import ffi from "ffi-napi";
import ref from "ref-napi";

const boolArray = ref.refType("bool");
const frArray = ref.refType("uint64");

const lib = ffi.Library("../crypto/target/release/libtest_circuit.dylib", {
    // setup_dpp_bn254(param_path, Length) -> bool
    setup_dpp_bn254: ["bool", ["string", "int", frArray]],
    prove_dpp_bn254: ["bool", ["string", frArray, frArray, boolArray, "int"]],
    verify_dpp_bn254: ["bool", ["string", frArray, "int"]],
    get_cc_vk_bn254: ["string", ["string"]],
    get_cc_proof_bn254: ["string", ["string"]],
    get_link_vk_bn254: ["string", ["string"]],
    get_link_proof_bn254: ["string", ["string"]],
});

export default lib;
