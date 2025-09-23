import lib from "../lib.js";
import Format from "../utils/format.js";

const param_path = "test/";

function getVk() {
    const vkJson = JSON.parse(lib.get_vk_bn254(param_path));
    const formattedVk = Format.vk(vkJson);

    return formattedVk;
}

function getProof() {
    const proofJson = JSON.parse(lib.get_proof_bn254(param_path));
    const formattedProof = Format.proof(proofJson);

    return formattedProof;
}

function setup(len) {
    console.time("Setup");
    if (lib.setup_dpp_bn254(param_path, len) != true) {
        throw new Error("Setup failed");
    } else {
        console.log("Setup succeeded");
    }
    console.timeEnd("Setup");
}

function prove(attr, cond, chk, len) {
    console.time("Prove");
    if (lib.prove_dpp_bn254(param_path, attr, cond, chk, len) != true) {
        throw new Error("Failed to generate proof");
    } else {
        console.log("Proof generation succeeded");
    }
    console.timeEnd("Prove");
}

function verify(cond, len) {
    console.time("Verify");
    lib.verify_dpp_bn254(param_path, cond, len);
    console.timeEnd("Verify");
}

const SnarkService = {
    param_path,
    getVk,
    getProof,
    setup,
    prove,
    verify,
};

export default SnarkService;
