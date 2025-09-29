import express from "express";
import dppRouter from "./dpp.router.js";
import tradeRouter from "./trade.router.js";

const rootRouter = express();
rootRouter.use("/dpp", dppRouter);
rootRouter.use("/trade", tradeRouter);

export default rootRouter;
