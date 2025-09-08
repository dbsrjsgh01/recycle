import ffi from "ffi-napi";

const lib = ffi.Library("../crypto/target/release/libtest_circuit.dylib", {
    setup_bn254: ["bool", ["string", "int"]],
    prove_bn254: ["bool", ["string"]],
    verify_bn254: ["bool", ["string"]],
    get_vk_bn254: ["string", ["string"]],
    get_proof_bn254: ["string", ["string"]],
});

export default lib;
