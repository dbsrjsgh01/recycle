import lib from "../lib.js";
import Format from "../utils/format.js";

const param_path = "test/";

function getCcVk() {
    const vkJson = JSON.parse(lib.get_cc_vk_bn254(param_path, false));
    const formattedVk = Format.cc_vk(vkJson);

    return formattedVk;
}

function getCcProof() {
    const proofJson = JSON.parse(lib.get_cc_proof_bn254(param_path, false));
    const formattedProof = Format.cc_proof(proofJson);

    return formattedProof;
}

function getLinkVk() {
    const vkJson = JSON.parse(lib.get_link_vk_bn254(param_path, false));
    const formattedVk = Format.link_vk(vkJson);

    return formattedVk;
}

function getLinkProof() {
    const proofJson = JSON.parse(lib.get_link_proof_bn254(param_path, false));
    const formattedProof = Format.link_proof(proofJson);

    return formattedProof;
}

function getCm() {
    const cmJson = JSON.parse(lib.get_cm_bn254(param_path));
    const formattedCm = Format.cm(cmJson);

    return formattedCm;
}

function setup(len, cond) {
    console.time("Setup");
    if (lib.setup_dpp_bn254(param_path, len, cond) != true) {
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

function verify(len) {
    console.time("Verify");
    let result = lib.verify_dpp_bn254(param_path, len);
    console.timeEnd("Verify");

    return result;
}

const DppService = {
    param_path,
    getCcVk,
    getCcProof,
    getLinkVk,
    getLinkProof,
    getCm,
    setup,
    prove,
    verify,
};

export default DppService;
