import ffi from "ffi-napi";
import ref from "ref-napi";
import path from "path";
import { fileURLToPath } from "url";
import {dirname} from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const boolArray = ref.refType("bool");
const frArray = ref.refType("uint64");

const libPath = {
    darwin: "libtest_circuit.dylib",
    linux: "libtest_circuit.so",
    win32: "test_circuit.dll",
}[process.platform];


const lib = ffi.Library(
    path.join(__dirname, "..", "..", "crypto", "target", "release", libPath), {
    // setup_dpp_bn254(param_path, Length, cond) -> bool
    setup_dpp_bn254: ["bool", ["string", "int", frArray]],
    // prove_dpp_bn254(param_path, attr, cond, chk, Length) -> bool
    prove_dpp_bn254: ["bool", ["string", frArray, frArray, boolArray, "int"]],
    // verify_dpp_bn254(param_path, cond, Length) -> bool
    verify_dpp_bn254: ["bool", ["string", "int"]],

    // setup_trade_bn254(param_path, Length, nf) -> bool
    setup_trade_bn254: ["bool", ["string", "int", frArray]],
    // prove_trade_bn254(param_path, attr, sk_s, cm_old, nf, Length) -> bool
    prove_trade_bn254: [
        "bool",
        ["string", frArray, frArray, frArray, frArray, "int"],
    ],
    // verify_trade_bn254(param_path, Length) -> bool
    verify_trade_bn254: ["bool", ["string", "int"]],
    // decrypt_trade_bn254() -> bool
    decrypt_trade_bn254: ["string", []],

    // get_*_bn254(param_path, boolean) -> string (true => values related to trade / false => values related to dpp)
    get_cc_vk_bn254: ["string", ["string", "bool"]],
    get_cc_proof_bn254: ["string", ["string", "bool"]],
    get_link_vk_bn254: ["string", ["string", "bool"]],
    get_link_proof_bn254: ["string", ["string", "bool"]],

    // mimc7_bn254(left, right) -> [u64; 4] : mimc7 hash function
    get_nf: ["void", [frArray, frArray, frArray]],
    get_random_values: ["void", [frArray]],

    // formatting unbounded u64 array into modulus number
    format_fr: ["void", [frArray]],

    // TEST
    trade_cc_snark_check: ["bool", [frArray, frArray, frArray, frArray, "int"]],
});

export default lib;
