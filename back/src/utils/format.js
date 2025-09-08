import Parse from "./parse.js";

function vk(vkJson) {
    const formattedVk = {};

    for (const key in vkJson) {
        if (vkJson.hasOwnProperty(key)) {
            const value = vkJson[key];

            if (key === "alpha" || key === "abc") {
                formattedVk[key] = Parse.parseAndFormatG1Value(value);
            } else if (key === "beta" || key === "gamma" || key === "delta") {
                formattedVk[key] = Parse.parseAndFormatG2Value(value);
            } else {
                formattedVk[key] = value;
            }
        }
    }

    return formattedVk;
}

function proof(proofJson) {
    const formattedProof = {};

    for (const key in proofJson) {
        if (proofJson.hasOwnProperty(key)) {
            const value = proofJson[key];
            if (key === "a" || key === "c") {
                formattedProof[key] = Parse.parseAndFormatG1Value(value);
            } else if (key === "b") {
                formattedProof[key] = Parse.parseAndFormatG2Value(value);
            } else {
                formattedProof[key] = value;
            }
        }
    }

    return formattedProof;
}

const Format = {
    vk,
    proof,
};

export default Format;
