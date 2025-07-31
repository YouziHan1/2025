const snarkjs = require("snarkjs");
const fs = require("fs");

async function main() {
    // 读取输入
    const input = JSON.parse(fs.readFileSync("input.json"));
    
    // 生成证明
    const { proof, publicSignals } = await snarkjs.groth16.prove("poseidon2_final.zkey", "witness.wtns");
    
    // 验证证明
    const vKey = JSON.parse(fs.readFileSync("verification_key.json"));
    const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    
    if (res === true) {
        console.log("验证成功!");
    } else {
        console.log("验证失败!");
    }
}

main().then(() => {
    process.exit(0);
}).catch((err) => {
    console.error(err);
    process.exit(1);
});
