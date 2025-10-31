import lib from "../lib.js";
import Format from "../utils/format.js";

const param_path = "test/";

function getCcVk() {
    const vkJson = JSON.parse(lib.get_cc_vk_bn254(param_path, true));
    const formattedVk = Format.cc_vk(vkJson);

    return formattedVk;
}

function getCcProof() {
    const proofJson = JSON.parse(lib.get_cc_proof_bn254(param_path, true));
    const formattedProof = Format.cc_proof(proofJson);

    return formattedProof;
}

function getLinkVk() {
    const vkJson = JSON.parse(lib.get_link_vk_bn254(param_path, true));
    const formattedVk = Format.link_vk(vkJson);

    return formattedVk;
}

function getLinkProof() {
    const proofJson = JSON.parse(lib.get_link_proof_bn254(param_path, true));
    const formattedProof = Format.link_proof(proofJson);

    return formattedProof;
}

function getNf(cm_old, sk_s, nf) {
    lib.get_nf(cm_old, sk_s, nf);
}

function setup(len, nf) {
    console.time("Setup");
    if (lib.setup_trade_bn254(param_path, len, nf) != true) {
        throw new Error("Setup failed");
    } else {
        console.log("Setup succeeded");
    }
    console.timeEnd("Setup");
}

function prove(attr, sk_s, cm_old, nf, len) {
    console.time("Prove");
    if (
        lib.prove_trade_bn254(param_path, attr, sk_s, cm_old, nf, len) != true
    ) {
        throw new Error("Failed to generate proof");
    } else {
        console.log("Proof generation succeeded");
    }
    console.timeEnd("Prove");
}

function verify(len) {
    console.time("Verify");
    lib.verify_trade_bn254(param_path, len);
    console.timeEnd("Verify");
}

function decrypt() {
    console.time("Decrypt");
    let dec_msg = lib.decrypt_trade_bn254();
    console.timeEnd("Decrypt");
    return dec_msg;
}

const SnarkService = {
    param_path,
    getCcVk,
    getCcProof,
    getLinkVk,
    getLinkProof,
    getNf,
    setup,
    prove,
    verify,
    decrypt,
};

export default SnarkService;
