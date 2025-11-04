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

function dec_msg(msgJson) {
    const formattedMsg = {};

    const msgJsonParse = JSON.parse(msgJson);
    console.log(msgJsonParse);

    for (const key in msgJson) {
        // if (msgJson.)
        console.log("[" + key + "] = " + msgJson[key]);
        
    }

    return formattedMsg;
}

function strToBigInt(str) {
    const encoder = new TextEncoder(); // UTF-8 인코딩
  const bytes = encoder.encode(str);
  
  let hex = '0x' + Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return BigInt(hex);
}

function bigIntToStr(num) {
    let hexString = num.toString(16);
    console.log(hexString);
     if (hexString.length % 2 !== 0) {
        throw new Error("Invalid hex string: must have an even number of characters");
    }

    const bytes = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i += 2) {
        bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
    }

    const decoder = new TextDecoder('utf-8');
    return decoder.decode(bytes);
}

const Format = {
    cc_vk,
    cc_proof,
    link_vk,
    link_proof,
    dec_msg,
    strToBigInt,
    bigIntToStr,
};

export default Format;
