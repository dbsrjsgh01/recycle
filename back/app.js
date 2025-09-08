import _ from "lodash";
import express from "express";
import rootRouter from "./src/routes/index.js";

const app = express();
const port = 3000;

app.use("/", rootRouter);

app.listen(port, () => {
    console.log("App start on ", port);
});

export default app;
