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

function getSetup(req, res) {
    SnarkService.setup(50);

    res.json({
        Setup: true,
    });
}

async function getProve(req, res) {
    SnarkService.prove();

    res.json({ Prove: true });
}

function getVerify(req, res) {
    SnarkService.verify();

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
