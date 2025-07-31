#!/bin/bash

set -e

echo "=== 计算正确的哈希值 ==="

cat > temp_input.json << EOF
{
    "preimage": ["1", "2"]
}
EOF
cat > temp_poseidon2.circom << 'EOF'
pragma circom 2.1.6;

template Pow5() {
    signal input in;
    signal output out;
    signal temp1;
    signal temp2;
    
    temp1 <== in * in;  
    temp2 <== temp1 * temp1;  
    out <== temp2 * in;  
}

template Poseidon2FullRound(round) {
    signal input state[3];
    signal output out[3];
    
    var M[3][3] = [
        [2, 1, 1],
        [1, 2, 1],
        [1, 1, 2]
    ];
    
    var C[3] = [round + 1, round + 2, round + 3];
    
    signal tmp[3];
    signal sbox[3];
    
    for (var i = 0; i < 3; i++) {
        tmp[i] <== state[i] + C[i];
    }
    
    component pow5[3];
    for (var i = 0; i < 3; i++) {
        pow5[i] = Pow5();
        pow5[i].in <== tmp[i];
        sbox[i] <== pow5[i].out;
    }
    
    for (var i = 0; i < 3; i++) {
        var sum = 0;
        for (var j = 0; j < 3; j++) {
            sum += M[i][j] * sbox[j];
        }
        out[i] <== sum;
    }
}

template Poseidon2PartialRound(round) {
    signal input state[3];
    signal output out[3];
    
    var M[3][3] = [
        [2, 1, 1],
        [1, 2, 1],
        [1, 1, 2]
    ];
    
    var C[3] = [round + 100, round + 101, round + 102];
    
    signal tmp[3];
    signal sbox[3];
    
    for (var i = 0; i < 3; i++) {
        tmp[i] <== state[i] + C[i];
    }
    
    component pow5 = Pow5();
    pow5.in <== tmp[0];
    sbox[0] <== pow5.out;
    sbox[1] <== tmp[1];
    sbox[2] <== tmp[2];
    
    for (var i = 0; i < 3; i++) {
        var sum = 0;
        for (var j = 0; j < 3; j++) {
            sum += M[i][j] * sbox[j];
        }
        out[i] <== sum;
    }
}

template Poseidon2Calculator() {
    signal input preimage[2];
    signal output hash;
    
    signal state[3];
    
    state[0] <== preimage[0];
    state[1] <== preimage[1];
    state[2] <== 0;
    
    signal fullRounds1[4][3];
    component fr1[4];
    for (var i = 0; i < 4; i++) {
        fr1[i] = Poseidon2FullRound(i);
        if (i == 0) {
            for (var j = 0; j < 3; j++) {
                fr1[i].state[j] <== state[j];
            }
        } else {
            for (var j = 0; j < 3; j++) {
                fr1[i].state[j] <== fr1[i-1].out[j];
            }
        }
        for (var j = 0; j < 3; j++) {
            fullRounds1[i][j] <== fr1[i].out[j];
        }
    }
    
    signal partialRounds[8][3];
    component pr[8];
    for (var i = 0; i < 8; i++) {
        pr[i] = Poseidon2PartialRound(i);
        if (i == 0) {
            for (var j = 0; j < 3; j++) {
                pr[i].state[j] <== fullRounds1[3][j];
            }
        } else {
            for (var j = 0; j < 3; j++) {
                pr[i].state[j] <== pr[i-1].out[j];
            }
        }
        for (var j = 0; j < 3; j++) {
            partialRounds[i][j] <== pr[i].out[j];
        }
    }
    
    signal fullRounds2[4][3];
    component fr2[4];
    for (var i = 0; i < 4; i++) {
        fr2[i] = Poseidon2FullRound(i + 4);
        if (i == 0) {
            for (var j = 0; j < 3; j++) {
                fr2[i].state[j] <== partialRounds[7][j];
            }
        } else {
            for (var j = 0; j < 3; j++) {
                fr2[i].state[j] <== fr2[i-1].out[j];
            }
        }
        for (var j = 0; j < 3; j++) {
            fullRounds2[i][j] <== fr2[i].out[j];
        }
    }
    
    hash <== fullRounds2[3][0];
}

component main = Poseidon2Calculator();
EOF

echo "编译临时电路"
circom temp_poseidon2.circom --r1cs --wasm --sym

echo "生成witness"
cd temp_poseidon2_js
node generate_witness.js temp_poseidon2.wasm ../temp_input.json ../temp_witness.wtns
cd ..

echo "提取公开输出"
snarkjs wtns export json temp_witness.wtns temp_witness.json

#提取hash值
HASH_VALUE=$(node -e "
const witness = require('./temp_witness.json');
console.log(witness[1]);
")

echo "计算出的hash值: $HASH_VALUE"

# 更新input.json
cat > input.json << EOF
{
    "hash": "$HASH_VALUE",
    "preimage": ["1", "2"]
}
EOF

echo "已更新input.json文件"

# 清理临时文件
rm -f temp_*.circom temp_*.json temp_*.wtns
rm -rf temp_poseidon2_js temp_poseidon2_cpp

