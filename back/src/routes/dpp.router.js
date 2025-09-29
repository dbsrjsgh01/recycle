import _ from "lodash";
import express from "express";
import expressAsyncHandler from "express-async-handler";
import DppService from "../service/dpp.service.js";

const dppRouter = express.Router();

dppRouter.get("/setup", getSetup);
dppRouter.get("/prove", expressAsyncHandler(getProve));
dppRouter.get("/verify", getVerify);
dppRouter.get("/get/cc/vk", getCcVk);
dppRouter.get("/get/cc/prf", getCcProof);
dppRouter.get("/get/link/vk", getLinkVk);
dppRouter.get("/get/link/prf", getLinkProof);

let attr = new BigUint64Array(50).fill(2n); // BigInteger
let cond = new BigUint64Array(50).fill(1n);
let chk = new Uint8Array(50).fill(1);
chk.set(new Uint8Array(25).fill(0), 25);

const attrBuf = Buffer.from(attr.buffer);
const condBuf = Buffer.from(cond.buffer);
const chkBuf = Buffer.from(chk.buffer);

function getSetup(req, res) {
    DppService.setup(50, condBuf);

    res.json({
        Setup: true,
    });
}

async function getProve(req, res) {
    DppService.prove(attrBuf, condBuf, chkBuf, 50);

    res.json({ Prove: true });
}

function getVerify(req, res) {
    DppService.verify(condBuf, 50);

    res.json({ Verification: "Success" });
}

function getCcVk(req, res) {
    const vkJson = DppService.getCcVk();
    res.json(vkJson);
}

function getCcProof(req, res) {
    const proofJson = DppService.getCcProof();
    res.json(proofJson);
}

function getLinkVk(req, res) {
    const vkJson = DppService.getLinkVk();
    res.json(vkJson);
}

function getLinkProof(req, res) {
    const proofJson = DppService.getLinkProof();
    res.json(proofJson);
}

export default dppRouter;
