import _ from "lodash";
import express from "express";
import expressAsyncHandler from "express-async-handler";
import SnarkService from "../service/snark.service.js";

const snarkRouter = express.Router();

snarkRouter.get("/setup", getSetup);
snarkRouter.get("/prove", expressAsyncHandler(getProve));
snarkRouter.get("/verify", getVerify);
snarkRouter.get("/get/cc/vk", getCcVk);
snarkRouter.get("/get/cc/prf", getCcProof);
snarkRouter.get("/get/link/vk", getLinkVk);
snarkRouter.get("/get/link/prf", getLinkProof);

let attr = new BigUint64Array(50).fill(2n); // BigInteger
let cond = new BigUint64Array(50).fill(1n);
let chk = new Uint8Array(50).fill(1);
chk.set(new Uint8Array(25).fill(0), 25);

const attrBuf = Buffer.from(attr.buffer);
const condBuf = Buffer.from(cond.buffer);
const chkBuf = Buffer.from(chk.buffer);

function getSetup(req, res) {
    SnarkService.setup(50, condBuf);

    res.json({
        Setup: true,
    });
}

async function getProve(req, res) {
    SnarkService.prove(attrBuf, condBuf, chkBuf, 50);

    res.json({ Prove: true });
}

function getVerify(req, res) {
    SnarkService.verify(condBuf, 50);

    res.json({ Verification: "Success" });
}

function getCcVk(req, res) {
    const vkJson = SnarkService.getCcVk();
    res.json(vkJson);
}

function getCcProof(req, res) {
    const proofJson = SnarkService.getCcProof();
    res.json(proofJson);
}

function getLinkVk(req, res) {
    const vkJson = SnarkService.getLinkVk();
    res.json(vkJson);
}

function getLinkProof(req, res) {
    const proofJson = SnarkService.getLinkProof();
    res.json(proofJson);
}

export default snarkRouter;
