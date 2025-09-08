import lib from "../lib.js";
import Format from "../utils/format.js";
import Parse from "../utils/parse.js";

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
    if (lib.setup_bn254(param_path, len) != true) {
        throw new Error("Setup failed");
    } else {
        console.log("Setup succeeded");
    }
    console.timeEnd("Setup");
}

function prove() {
    console.time("Prove");
    if (lib.prove_bn254(param_path) != true) {
        throw new Error("Failed to generate proof");
    } else {
        console.log("Proof generation succeeded");
    }
    console.timeEnd("Prove");
}

function verify() {
    console.time("Verify");
    lib.verify_bn254(param_path);
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
