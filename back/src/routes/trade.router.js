import _ from "lodash";
import express from "express";
import expressAsyncHandler from "express-async-handler";
import TradeService from "../service/trade.service.js";
import Format from "../utils/format.js";

const tradeRouter = express.Router();

tradeRouter.post("/setup", expressAsyncHandler(setup));
tradeRouter.post("/prove", expressAsyncHandler(prove));
tradeRouter.post("/verify", expressAsyncHandler(verify));
tradeRouter.post("/decrypt", expressAsyncHandler(decrypt));
tradeRouter.post("/get/nf", expressAsyncHandler(nf));

// 아래는 dat 파일을 json 형식으로 바꿔 Get-method 호출; 호출은 Rust library 내의 get-method 함수 정의됨
tradeRouter.get("/get/ccvk", getCcVk);
tradeRouter.get("/get/ccprf", getCcProof);
tradeRouter.get("/get/linkvk", getLinkVk);
tradeRouter.get("/get/linkprf", getLinkProof);

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

    console.log("nf: \t", nf);

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
    const attr = new BigUint64Array(attrStr.map((x) => Format.strToBigInt(x)));
    const attrBuf = Buffer.from(attr.buffer);
    const cmOldXStr = req.body.cm_old_x;
    const cm_old_x = new BigUint64Array(cmOldXStr.map((x) => BigInt(x)));
    const cmOldXBuf = Buffer.from(cm_old_x.buffer);
    const cmOldYStr = req.body.cm_old_y;
    const cm_old_y = new BigUint64Array(cmOldYStr.map((x) => BigInt(x)));
    const cmOldYBuf = Buffer.from(cm_old_y.buffer);
    const skSStr = req.body.sk_s;
    const sk_s = new BigUint64Array(skSStr.map((x) => BigInt(x)));
    const skSBuf = Buffer.from(sk_s.buffer);
    const nfStr = req.body.nf;
    const nf = new BigUint64Array(nfStr.map((x) => BigInt(x)));
    const nfBuf = Buffer.from(nf.buffer);

    const len = req.body.len;

    TradeService.prove(attrBuf, skSBuf, cmOldXBuf, cmOldYBuf, nfBuf, len);

    res.json({ Prove: true });
}

async function verify(req, res) {
    const len = req.body.len;

    let result = TradeService.verify(len);

    res.json({ Verification: result });
}

async function nf(req, res) {
    const cmOldXStr = req.body.cm_old_x;
    const cm_old_x = new BigUint64Array(cmOldXStr.map((x) => BigInt(x)));
    const cmOldXBuf = Buffer.from(cm_old_x.buffer);
    const cmOldYStr = req.body.cm_old_y;
    const cm_old_y = new BigUint64Array(cmOldYStr.map((x) => BigInt(x)));
    const cmOldYBuf = Buffer.from(cm_old_y.buffer);
    const skSStr = req.body.sk_s;
    const sk_s = new BigUint64Array(skSStr.map((x) => BigInt(x)));
    const skSBuf = Buffer.from(sk_s.buffer);
    const nfStr = req.body.nf;
    const nf = new BigUint64Array(nfStr.map((x) => BigInt(x)));
    const nfBuf = Buffer.from(nf.buffer);

    TradeService.getNf(skSBuf, cmOldXBuf, cmOldYBuf, nfBuf);

    res.json({ nf: Array.from(nf, (x) => x.toString()) });
    
    return nf;
}

async function decrypt(req, res) {
    let dec_msg = TradeService.decrypt();

    res.json({ Decryption: "Success", MSG: dec_msg });
}

// http://localhost:10801/trade/get/ccvk
function getCcVk(req, res) {
    const vkJson = TradeService.getCcVk();
    res.json(vkJson);
}

// http://localhost:10801/trade/get/ccprf
function getCcProof(req, res) {
    const proofJson = TradeService.getCcProof();
    res.json(proofJson);
}

// http://localhost:10801/trade/get/linkvk
function getLinkVk(req, res) {
    const vkJson = TradeService.getLinkVk();
    res.json(vkJson);
}

// http://localhost:10801/trade/get/linkprf
function getLinkProof(req, res) {
    const proofJson = TradeService.getLinkProof();
    res.json(proofJson);
}

export default tradeRouter;
