pragma circom 2.1.6;

// 辅助模板：计算5次方
template Pow5() {
    signal input in;
    signal output out;
    signal temp1;
    signal temp2;
    
    temp1 <== in * in;  // x^2
    temp2 <== temp1 * temp1;  // x^4
    out <== temp2 * in;  // x^5
}

// Poseidon2 轮函数
// 根据论文Table 1，使用参数(n,t,d)=(256,3,5)
// n: 有限域大小为 2^n = 2^256
// t: 宽度参数(state size) = 3
// d: S-box 的次数 = 5
// R_F: 全轮数 = 8
// R_P: 部分轮数 = 56

template Poseidon2FullRound(round) {
    signal input state[3];
    signal output out[3];
    
    // 简化的MDS矩阵
    var M[3][3] = [
        [2, 1, 1],
        [1, 2, 1],
        [1, 1, 2]
    ];
    
    // 简化的轮常量
    var C[3] = [round + 1, round + 2, round + 3];
    
    // 临时状态
    signal tmp[3];
    signal sbox[3];
    
    // AddRoundConstants
    for (var i = 0; i < 3; i++) {
        tmp[i] <== state[i] + C[i];
    }
    
    // S-box (x^5)
    component pow5[3];
    for (var i = 0; i < 3; i++) {
        pow5[i] = Pow5();
        pow5[i].in <== tmp[i];
        sbox[i] <== pow5[i].out;
    }
    
    // MDS矩阵混淆
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
    
    // MDS矩阵
    var M[3][3] = [
        [2, 1, 1],
        [1, 2, 1],
        [1, 1, 2]
    ];
    
    // 轮常量
    var C[3] = [round + 100, round + 101, round + 102];
    
    signal tmp[3];
    signal sbox[3];
    
    // 1. AddRoundConstants
    for (var i = 0; i < 3; i++) {
        tmp[i] <== state[i] + C[i];
    }
    
    // 2. S-box (x^5) 只应用于第一个状态元素
    component pow5 = Pow5();
    pow5.in <== tmp[0];
    sbox[0] <== pow5.out;
    sbox[1] <== tmp[1];  // 其他元素保持不变
    sbox[2] <== tmp[2];
    
    // 3. MDS矩阵混淆
    for (var i = 0; i < 3; i++) {
        var sum = 0;
        for (var j = 0; j < 3; j++) {
            sum += M[i][j] * sbox[j];
        }
        out[i] <== sum;
    }
}

template Poseidon2Hasher() {
    // 输入信号
    signal input hash;          // 公开输入 - poseidon2哈希值
    signal input preimage[2];   // 私密输入 - 原像
    
    // poseidon2 状态数组
    signal state[3];  // t=3的状态大小
    
    // 初始化状态
    state[0] <== preimage[0];
    state[1] <== preimage[1];
    state[2] <== 0;  // padding
    
    // 前半部分全轮变换 (R_F/2 = 4轮)
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
    
    // 轮变换
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
    
    // 后半部分全轮变换
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
    
    // 验证哈希值
    hash === fullRounds2[3][0];
}

component main = Poseidon2Hasher();
