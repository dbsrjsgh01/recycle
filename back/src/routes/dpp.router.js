import _ from "lodash";
import express from "express";
import expressAsyncHandler from "express-async-handler";
import DppService from "../service/dpp.service.js";
import Format from "../utils/format.js";

const dppRouter = express.Router();

dppRouter.post("/setup", expressAsyncHandler(setup));
dppRouter.post("/prove", expressAsyncHandler(prove));
dppRouter.post("/verify", expressAsyncHandler(verify));

// 아래는 dat 파일을 json 형식으로 바꿔 Get-method 호출; 호출은 Rust library 내의 get-method 함수 정의됨
dppRouter.get("/get/ccvk", getCcVk);
dppRouter.get("/get/ccprf", getCcProof);
dppRouter.get("/get/linkvk", getLinkVk);
dppRouter.get("/get/linkprf", getLinkProof);
dppRouter.get("/get/cm", getCm);

async function setup(req, res) {
    /**
     * BigInt type 변수들은 그대로 옮길 수 없음.
     * 방법 1) BigInt => String 변환 후 전달
     * 방법 2) BigIntArray의 주소값을 base64로 인코딩하여 전달
     *
     * 입력값을 무사히 받았을 때 Rust library에서 주소값 형태로 입력을 받기 때문에 buffer로 건네 줄 예정
     * WARNING! 현재 req에 대한 에러 처리는 생략
     */
    const condStr = req.body.cond;
    const cond = new BigUint64Array(condStr.map((x) => Format.strToBigInt(x)));
    const condBuf = Buffer.from(cond.buffer);
    const len = req.body.len;
    const isEq = req.body.isEq;

    DppService.setup(len, condBuf, isEq);

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
    const condStr = req.body.cond;
    const cond = new BigUint64Array(condStr.map((x) => Format.strToBigInt(x)));
    const condBuf = Buffer.from(cond.buffer);

    const len = req.body.len;

    /**
     * Uint8Array는 UTF-8로 이루어져 있기에 string을 Number로 바로 바꿀 수 있습니다.
     *
     * WARNING! 현재 req에 대한 에러 처리는 생략
     */
    const chkStr = req.body.chk;
    const chk = new Uint8Array(chkStr.map((x) => Number(x)));
    const chkBuf = Buffer.from(chk.buffer);

    const isLatest = req.body.isLatest;
    const isEq = req.body.isEq;

    DppService.prove(attrBuf, condBuf, chkBuf, len, isLatest, isEq);

    res.json({ Prove: true });
}

async function verify(req, res) {
    const len = req.body.len;
    const isLatest = req.body.isLatest;

    let result = DppService.verify(len, isLatest);

    res.json({ Verification: result });
}

// http://localhost:10801/dpp/get/ccvk
function getCcVk(req, res) {
    const vkJson = DppService.getCcVk();
    res.json(vkJson);
}

// http://localhost:10801/dpp/get/ccprf
function getCcProof(req, res) {
    const proofJson = DppService.getCcProof();
    res.json(proofJson);
}

// http://localhost:10801/dpp/get/linkvk
function getLinkVk(req, res) {
    const vkJson = DppService.getLinkVk();
    res.json(vkJson);
}

// http://localhost:10801/dpp/get/linkvk
function getLinkProof(req, res) {
    const proofJson = DppService.getLinkProof();
    res.json(proofJson);
}

// http://localhost:10801/dpp/get/cm
function getCm(req, res) {
    const cmJson = DppService.getCm();
    res.json(cmJson);
}

export default dppRouter;
