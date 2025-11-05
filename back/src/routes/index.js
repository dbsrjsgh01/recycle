import express from "express";
import dppRouter from "./dpp.router.js";
import tradeRouter from "./trade.router.js";
import lib from "../lib.js";

const rootRouter = express.Router();
rootRouter.use("/dpp", dppRouter);
rootRouter.use("/trade", tradeRouter);

// DEFINE TEST VARIABLES AND FETCH
const attrLen = 50;
// ========== DPP variables ==========
let attr = new BigUint64Array(attrLen).fill(0n); // BigInteger
let cond = new BigUint64Array(attrLen).fill(0n);
let chk = new Uint8Array(attrLen).fill(1);
chk.set(new Uint8Array(25).fill(0), 25);

// ============== Test ==============
for (let i = 0; i < attrLen / 2; i++) {
    attr[i] = BigInt(i);
}
for (let i  = attrLen / 2 ; i < attrLen; i++) {
    cond[i] = BigInt(i);
}

// ========= Trade variables =========
let sk_s = new BigUint64Array(4);
let cm_old_x = new BigUint64Array(4);
let cm_old_y = new BigUint64Array(4);
let nf = new BigUint64Array(4);

// Test 용으로 임의값 추출
lib.get_random_values(sk_s);
lib.get_random_values(cm_old_x);
lib.get_random_values(cm_old_y);

// Rust library에서 주소값 형태로 입력을 받기 때문에 buffer로 건네 줄 예정
let skSBuf = Buffer.from(sk_s.buffer);
let cmOldXBuf = Buffer.from(cm_old_x.buffer);
let cmOldYBuf = Buffer.from(cm_old_y.buffer);
let nfBuf = Buffer.from(nf.buffer);

lib.get_nf(skSBuf, cmOldXBuf, cmOldYBuf, nfBuf);

console.log("Attr: \t", attr);
console.log("Cond: \t", cond);
console.log("Chk: \t", chk);
console.log("sk_s: \t", sk_s);
console.log("cm_old_x: \t", cm_old_x);
console.log("cm_old_y: \t", cm_old_y);
console.log("nf: \t", nf);

/**
 * http://localhost:10801/setup
 * 1. DPP 서킷과 거래 서킷에 대해 공개 파라미터 생성
 *    /back/test (dpp.cc_vk.dat, dpp.link_vk.dat / trade.cc_vk.dat, trade.link_vk.dat)
 * 2. 암호화/복호화 키 생성
 *    /back/test (trade.enc_sk.dat 저장)
 * 3. 암호화 키 (공개 키; enc_pk), 증명 키 (*.cc_pk, *.link_pk)는 Rust 내 Mutex 형태로 언제든 접근 가능하도록 설정
 */
rootRouter.get("/setup", async (req, res) => {
    /**
     * BigInt type 변수들은 그대로 옮길 수 없음.
     * 방법 1) BigInt => String 변환 후 전달
     * 방법 2) BigIntArray의 주소값을 base64로 인코딩하여 전달
     */
    const condStr = Array.from(cond, (x) => x.toString());

    // (DPP 서킷) 공개 파라미터 생성 요청, cond은 (조건값) 공개 입력값으로 상수값으로 저장할 예정
    const resDpp = await fetch("http://localhost:10801/dpp/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cond: condStr, len: attrLen }),
    });

    // (DPP 서킷) 결과 확인 용
    const resultDpp = await resDpp.json();

    // (거래 서킷) 공개 파라미터 생성 요청, nf는 (조건값) 공개 입력값
    const nfStr = Array.from(nf, (x) => x.toString());

    // (거래 서킷) 결과 확인 용
    const resTrade = await fetch("http://localhost:10801/trade/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nf: nfStr, len: attrLen }),
    });

    const resultTrade = await resTrade.json();

    console.log(resultDpp, resultTrade);
    res.json({ dpp: resultDpp, trade: resultTrade });
});

/**
 * http://localhost:10801/prove-dpp
 * DPP 서킷 약정값 및 증명값 생성
 */
rootRouter.get("/prove-dpp", async (req, res) => {
    /**
     * BigInt type 변수들은 그대로 옮길 수 없음.
     *
     * 방법 1) BigInt => String 변환 후 전달
     *
     * 방법 2) BigIntArray의 주소값을 base64로 인코딩하여 전달
     */
    const attrStr = Array.from(attr, (x) => x.toString());
    const condStr = Array.from(cond, (x) => x.toString());
    const chkStr = Array.from(chk, (x) => x.toString());

    /**
     * (DPP 서킷) 약정값 및 증명값 생성 요청 (Commit-and-prove)
     *
     * /back/test: dpp.cc_proof.dat, dpp.link_proof.dat, dpp.cm.dat 생성
     */
    const resDppProve = await fetch("http://localhost:10801/dpp/prove", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attr: attrStr, cond: condStr, chk: chkStr, len: attrLen }),
    });

    // (DPP 서킷) 증명 결과 확인용
    const resultDppProve = await resDppProve.json();

    let testVal = [];
    for (let i = 0; i < attrLen; i++) {
        let attrVal = [attrStr[4*i], attrStr[4*i+1], attrStr[4*i+2], attrStr[4*i+3]];
        let condVal = [condStr[4*i], condStr[4*i+1], condStr[4*i+2], condStr[4*i+3]];
        testVal.push(...[attrVal, condVal, chk[i]]);
    }

    console.log(resultDppProve);
    res.json({ "Prove Status": resultDppProve, "Test Values": testVal });
});

/**
 * http://localhost:10801/prove-trade
 * 거래 서킷 약정값 및 암호문, 증명값 생성
 */
rootRouter.get("/prove-trade", async (req, res) => {
    /**
     * BigInt type 변수들은 그대로 옮길 수 없음.
     *
     * 방법 1) BigInt => String 변환 후 전달
     *
     * 방법 2) BigIntArray의 주소값을 base64로 인코딩하여 전달
     */
    const attrStr = Array.from(attr, (x) => x.toString());
    const skSStr = Array.from(sk_s, (x) => x.toString());
    const cmOldXStr = Array.from(cm_old_x, (x) => x.toString());
    const cmOldYStr = Array.from(cm_old_y, (x) => x.toString());
    const nfStr = Array.from(nf, (x) => x.toString());

    /**
     * (거래 서킷) 약정값 및 암호문, 증명값 생성 요청 (Encrypt-and-prove)
     *
     * /back/test: trade.cc_proof.dat, trade.link_proof.dat, trade.ct.dat 생성
     */
    const resTradeProve = await fetch("http://localhost:10801/trade/prove", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            attr: attrStr,
            sk_s: skSStr,
            cm_old_x: cmOldXStr,
            cm_old_y: cmOldYStr,
            nf: nfStr,
            len: attrLen,
        }),
    });

    // (거래 서킷) 증명 결과 확인용
    const resultTradeProve = await resTradeProve.json();

    console.log(resultTradeProve);
    res.json({ "Prove Status": resultTradeProve });
});

rootRouter.get("/verify-dpp", async (req, res) => {
    const resDppVerify = await fetch ("http://localhost:10801/dpp/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            len: attrLen,
        }),
    });

    const resultDppVerify = await resDppVerify.json();

    console.log(resultDppVerify);
    res.json({ "Verification": resultDppVerify});
})

rootRouter.get("/verify-trade", async (req, res) => {
    const resTradeVerify = await fetch ("http://localhost:10801/trade/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            len: attrLen,
        }),
    });

    const resultTradeVerify = await resTradeVerify.json();

    console.log(resultTradeVerify);
    res.json({ "Verification": resultTradeVerify});
})

rootRouter.get("/decrypt", async (req, res) => {
    const resTradeDecrypt = await fetch ("http://localhost:10801/trade/decrypt", {
        method: "POST",
    });

    const resultTradeDecrypt  = await resTradeDecrypt.json();

    console.log(resultTradeDecrypt);
    res.json({"Decryption Status": resultTradeDecrypt});
})

export default rootRouter;
