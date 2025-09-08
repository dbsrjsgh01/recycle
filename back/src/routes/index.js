import express from "express";
import snarkRouter from "./snark.router.js";

const rootRouter = express();
rootRouter.use("/snark", snarkRouter);

export default rootRouter;
