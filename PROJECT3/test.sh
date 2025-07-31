#!/bin/bash

set -e


# 检查文件是否存在
if [ ! -f "poseidon2.circom" ]; then
    echo "错误: poseidon2.circom 文件不存在"
    exit 1
fi

if [ ! -f "input.json" ]; then
    echo "错误: input.json 文件不存在"
    exit 1
fi

circom poseidon2.circom --r1cs --wasm --sym --c

if [ ! -d "poseidon2_js" ]; then
    echo "错误: 编译失败，没有生成 poseidon2_js 目录"
    exit 1
fi

cd poseidon2_js
node generate_witness.js poseidon2.wasm ../input.json ../witness.wtns
cd ..

snarkjs r1cs info poseidon2.r1cs


snarkjs r1cs print poseidon2.r1cs poseidon2.sym

echo "=== 编译和witness生成成功! ==="

