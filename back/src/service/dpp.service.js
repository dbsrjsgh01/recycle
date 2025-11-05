import lib from "../lib.js";
import Format from "../utils/format.js";

let stamp = 0;
let param_path = "";

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

function setup(len, cond, isEq) {
    stamp = +new Date();
    param_path = Format.path(stamp.toString());
    console.time("Setup");
    let isSet = true;
    if (isEq == true) {
        isSet = lib.setup_dpp_bn254(param_path, len, cond);
    } else {
        isSet = lib.setup_dpp_ge_bn254(param_path, len, cond);
    }

    if (isSet != true) {
        throw new Error("Setup failed");
    } else {
        console.log("Setup succeeded");
    }
    console.timeEnd("Setup");
}

function eqProve(attr, cond, chk, len, isLatest) {
    console.time("Prove");
    let isProven = true;
    if (isLatest == true) {
        isProven = lib.prove_dpp_bn254_latest(param_path, attr, cond, chk, len);
    } 
    else {
        isProven = lib.prove_dpp_bn254(param_path, attr, cond, chk, len);
    }
    return isProven;
}

function geProve(attr, cond, chk, len, isLatest) {
    console.time("Prove");
    let isProven = true;
    if (isLatest == true) {
        isProven = lib.prove_dpp_ge_bn254_latest(param_path, attr, cond, chk, len);
    } 
    else {
        isProven = lib.prove_dpp_ge_bn254(param_path, attr, cond, chk, len);
    }
    return isProven;
}

function prove(attr, cond, chk, len, isLatest, isEq) {
    console.time("Prove");
    let isProven = true;
    if (isEq == true) {
        isProven = eqProve(attr, cond, chk, len, isLatest);
    } 
    else {
        isProven = geProve(attr, cond, chk, len, isLatest);
    }

    if (isProven != true) {
        throw new Error("Failed to generate proof");
    } else {
        console.log("Proof generation succeeded");
    }

    console.timeEnd("Prove");
}

function verify(len, isLatest) {
    console.time("Verify");
    let result = true;
    if (isLatest == true) {
        result = lib.verify_dpp_bn254_latest(param_path, len);
    } else {
        result = lib.verify_dpp_bn254(param_path, len);
    }
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
