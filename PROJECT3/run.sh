#!/bin/bash

# 确保脚本在错误时停止
set -e

echo "生成 witness..."
# 生成 witness
node poseidon2_js/generate_witness.js poseidon2_js/poseidon2.wasm input.json witness.wtns

echo "生成证明..."
# 生成证明
snarkjs groth16 prove poseidon2_final.zkey witness.wtns proof.json public.json

echo "验证证明..."
# 运行验证脚本
node verify.js

echo "完成!"
