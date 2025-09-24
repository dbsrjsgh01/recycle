import Parse from "./parse.js";

function cc_vk(vkJson) {
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

function cc_proof(proofJson) {
    const formattedProof = {};

    for (const key in proofJson) {
        if (proofJson.hasOwnProperty(key)) {
            const value = proofJson[key];

            if (key === "a" || key === "c" || key === "cm") {
                formattedProof[key] = Parse.parseAndFormatG1Value(value);
            } else if (key === "b") {
                formattedProof[key] = Parse.parseAndFormatG2Value(value);
            }
        }
    }

    return formattedProof;
}

function link_vk(vkJson) {
    const formattedJson = {};

    for (const key in vkJson) {
        if (vkJson.hasOwnProperty(key)) {
            const value = vkJson[key];
            formattedJson[key] = Parse.parseAndFormatG2Value(value);
        }
    }

    return formattedJson;
}

function link_proof(proofJson) {
    const formattedProof = {};

    // Loop through the keys in the proofJson.
    for (const key in proofJson) {
        if (proofJson.hasOwnProperty(key)) {
            const value = proofJson[key];
            formattedProof[key] = Parse.parseAndFormatG1Value(value);
        }
    }

    return formattedProof;
}

const Format = {
    cc_vk,
    cc_proof,
    link_vk,
    link_proof,
};

export default Format;
