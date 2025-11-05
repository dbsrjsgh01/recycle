import _ from "lodash";
import express from "express";
import rootRouter from "./src/routes/index.js";

const app = express();
const port = 10801;

// string file을 json 형태로 전송할 예정
app.use(express.json({ limit: "5mb" }));
app.use("/", rootRouter);

app.listen(port, () => {
    console.log("App start on ", port);
});

export default app;
