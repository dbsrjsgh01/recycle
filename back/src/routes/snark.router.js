import _ from "lodash";
import express from "express";
import expressAsyncHandler from "express-async-handler";
import SnarkService from "../service/snark.service.js";

const snarkRouter = express.Router();

snarkRouter.get("/setup", getSetup);
snarkRouter.get("/prove", expressAsyncHandler(getProve));
snarkRouter.get("/verify", getVerify);
snarkRouter.get("/get/vk", getVk);
snarkRouter.get("/get/prf", getProof);

let attr = new BigUint64Array(50).fill(2n);
let cond = new BigUint64Array(50).fill(1n);
let chk = new Uint8Array(50).fill(1);
chk.set(new Uint8Array(25).fill(0), 25);

const attrBuf = Buffer.from(attr.buffer);
const condBuf = Buffer.from(cond.buffer);
const chkBuf = Buffer.from(chk.buffer);

function getSetup(req, res) {
    SnarkService.setup(50);

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

function getVk(req, res) {
    const vkJson = SnarkService.getVk();
    res.json(vkJson);
}

function getProof(req, res) {
    const proofJson = SnarkService.getProof();
    res.json(proofJson);
}

export default snarkRouter;
