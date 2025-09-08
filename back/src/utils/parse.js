import lib from "../lib.js";
import Format from "./format.js";
import param_path from "../service/snark.service.js";

async function getJsonParam(type) {
    const json = JSON.parse(lib[`get_${type}_bn254`](param_path));
    return Format[`${type}`](json);
}

async function getParamArray(type) {
    const formattedJson = await getJsonParam(type);

    const paramStrArr = [];

    if (type === "vk") {
        /// alpha, beta, gamma, delta, abc, eta_gamma_inv_g1, eta_delta_inv_g1
        ["alpha", "beta", "delta"].forEach((key) => {
            formattedJson[key].forEach((item) => {
                paramStrArr.push(...item);
            });
        });

        paramStrArr.push(...formattedJson.abc[0]);

        ["gamma"].forEach((key) => {
            formattedJson[key].forEach((item) => {
                paramStrArr.push(...item);
            });
        });
        paramStrArr.push(...formattedJson.abc[formattedJson.abc.length - 1]);
    } else if (type === "proof") {
        ["a", "b", "c"].forEach((key) => {
            formattedJson[key].forEach((item) => {
                paramStrArr.push(...item);
            });
        });
    }
    return paramStrArr.map((item) => item.toString());
}

async function toVkParam() {
    return await getParamArray("vk");
}

async function toProofParam() {
    return await getParamArray("proof");
}
function parseColumns(data, selectColumns) {
    return data.map((item) => {
        const newItem = {};
        selectColumns.forEach((column) => {
            if (item.hasOwnProperty(column)) {
                newItem[column] = item[column];
            }
        });
        return newItem;
    });
}

function parseDataFromJsonArr(jsonArr, key) {
    let vec = [];
    for (let i = 0; i < jsonArr.length; i++) {
        vec.push(jsonArr[i][key]);
    }

    return vec;
}

// Function to parse and format a single value.
function parseAndFormatG1Value(value) {
    const regex = /\(([^)]+)\)/g;
    const matches = Array.from(value.matchAll(regex));

    const formattedValue = [];

    for (const match of matches) {
        const elements = match[1]
            .split(",")
            .map((str) => BigInt(str.trim()).toString());
        formattedValue.push(elements);
    }

    return formattedValue;
}

function parseAndFormatG2Value(value) {
    const regex = /QuadExtField\((-?\d+) \+ (-?\d+) \* u\)/g;
    const matches = Array.from(value.matchAll(regex));

    let formattedValue;

    if (matches.length > 0) {
        formattedValue = matches.map((match) => [match[2], match[1]]);
    } else {
        formattedValue = [];
    }

    return formattedValue;
}

const Parse = {
    toVkParam,
    toProofParam,
    parseDataFromJsonArr,
    parseAndFormatG1Value,
    parseAndFormatG2Value,
};

export default Parse;
