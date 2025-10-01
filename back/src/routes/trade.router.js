import _ from "lodash";
import express from "express";
import expressAsyncHandler from "express-async-handler";
import TradeService from "../service/trade.service.js";

const tradeRouter = express.Router();

tradeRouter.post("/setup", expressAsyncHandler(setup));
tradeRouter.post("/prove", expressAsyncHandler(prove));
tradeRouter.post("/verify", expressAsyncHandler(verify));
tradeRouter.get("/get/cc/vk", getCcVk);
tradeRouter.get("/get/cc/prf", getCcProof);
tradeRouter.get("/get/link/vk", getLinkVk);
tradeRouter.get("/get/link/prf", getLinkProof);

async function setup(req, res) {
    /**
     * BigInt type 변수들은 그대로 옮길 수 없음.
     * 방법 1) BigInt => String 변환 후 전달
     * 방법 2) BigIntArray의 주소값을 base64로 인코딩하여 전달
     *
     * 입력값을 무사히 받았을 때 Rust library에서 주소값 형태로 입력을 받기 때문에 buffer로 건네 줄 예정
     * WARNING! 현재 req에 대한 에러 처리는 생략
     */
    const nfStr = req.body.nf;
    const nf = new BigUint64Array(nfStr.map((x) => BigInt(x)));
    const nfBuf = Buffer.from(nf.buffer);

    const len = req.body.len;

    TradeService.setup(len, nfBuf);

    res.json({
        Setup: true,
    });
}

async function prove(req, res) {
    /**
     * BigInt type 변수들은 그대로 옮길 수 없음.
     *
     * 방법 1) BigInt => String 변환 후 전달
     *
     * 방법 2) BigIntArray의 주소값을 base64로 인코딩하여 전달
     *
     * 입력값을 무사히 받았을 때 Rust library에서 주소값 형태로 입력을 받기 때문에 buffer로 건네 줄 예정
     *
     * WARNING! 현재 req에 대한 에러 처리는 생략
     */
    const attrStr = req.body.attr;
    const attr = new BigUint64Array(attrStr.map((x) => BigInt(x)));
    const attrBuf = Buffer.from(attr.buffer);
    const cmOldStr = req.body.cm_old;
    const cm_old = new BigUint64Array(cmOldStr.map((x) => BigInt(x)));
    const cmOldBuf = Buffer.from(cm_old.buffer);
    const skSStr = req.body.sk_s;
    const sk_s = new BigUint64Array(skSStr.map((x) => BigInt(x)));
    const skSBuf = Buffer.from(sk_s.buffer);
    const nfStr = req.body.nf;
    const nf = new BigUint64Array(nfStr.map((x) => BigInt(x)));
    const nfBuf = Buffer.from(nf.buffer);

    TradeService.prove(attrBuf, skSBuf, cmOldBuf, nfBuf, 50);

    res.json({ Prove: true });
}

async function verify(req, res) {
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
