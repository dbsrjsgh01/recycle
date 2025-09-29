import _ from "lodash";
import express from "express";
import expressAsyncHandler from "express-async-handler";
import TradeService from "../service/trade.service.js";
import lib from "../lib.js";

const tradeRouter = express.Router();

tradeRouter.get("/setup", getSetup);
tradeRouter.get("/prove", expressAsyncHandler(getProve));
tradeRouter.get("/verify", getVerify);
tradeRouter.get("/get/cc/vk", getCcVk);
tradeRouter.get("/get/cc/prf", getCcProof);
tradeRouter.get("/get/link/vk", getLinkVk);
tradeRouter.get("/get/link/prf", getLinkProof);

let attr = new BigUint64Array(50).fill(2n); // BigInteger
let sk_s = new BigUint64Array(1);
let cm_old = new BigUint64Array(1);
let nf = new BigUint64Array(4);

crypto.getRandomValues(sk_s);
crypto.getRandomValues(cm_old);

const attrBuf = Buffer.from(attr.buffer);
const skSBuf = Buffer.from(sk_s.buffer);
const cmOldBuf = Buffer.from(cm_old.buffer);
let nfBuf = Buffer.from(nf.buffer);
lib.get_nf(cmOldBuf, skSBuf, nfBuf);

console.log(sk_s);
console.log(cm_old);

function getSetup(req, res) {
    TradeService.setup(50, nfBuf);

    res.json({
        Setup: true,
    });
}

async function getProve(req, res) {
    TradeService.prove(attrBuf, skSBuf, cmOldBuf, nfBuf, 50);

    res.json({ Prove: true });
}

function getVerify(req, res) {
    TradeService.verify(50);

    res.json({ Verification: "Success" });
}

function getCcVk(req, res) {
    const vkJson = TradeService.getCcVk();
    res.json(vkJson);
}

function getCcProof(req, res) {
    const proofJson = TradeService.getCcProof();
    res.json(proofJson);
}

function getLinkVk(req, res) {
    const vkJson = TradeService.getLinkVk();
    res.json(vkJson);
}

function getLinkProof(req, res) {
    const proofJson = TradeService.getLinkProof();
    res.json(proofJson);
}

export default tradeRouter;
