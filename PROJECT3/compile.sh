#!/bin/bash

# 确保脚本在错误时停止
set -e

if ! command -v curl &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y curl
fi

if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

if ! command -v circom &> /dev/null; then
    echo "正在安装 circom..."
    git clone https://github.com/iden3/circom.git
    cd circom
    cargo build --release
    sudo cp target/release/circom /usr/local/bin/
    cd ..
    rm -rf circom
fi

if ! command -v snarkjs &> /dev/null; then
    echo "正在安装 snarkjs..."
    npm install -g snarkjs
fi

# 安装项目依赖
npm init -y
npm install snarkjs

echo "正在下载 circomlib..."
if [ ! -d "node_modules/circomlib" ]; then
    npm install circomlib
fi


# 编译电路
circom poseidon2.circom --r1cs --wasm --sym

snarkjs powersoftau new bn128 12 pot12_0000.ptau -v

# 第一阶段贡献随机性
echo "随机贡献" | snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v

# 第二阶段
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v

echo "生成proving key和verification key..."
# 生成proving key和verification key
snarkjs groth16 setup poseidon2.r1cs pot12_final.ptau poseidon2_0000.zkey

# 贡献随机性
echo "随机贡献" | snarkjs zkey contribute poseidon2_0000.zkey poseidon2_final.zkey --name="1st Contributor" -v

# 导出verification key
snarkjs zkey export verificationkey poseidon2_final.zkey verification_key.json

echo "编译完成"
