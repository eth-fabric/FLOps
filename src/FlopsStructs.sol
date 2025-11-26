// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

struct BlockState {
    bool broken;
    bytes32 rollingHash;
}

struct FlopsData {
    uint64 blockNumber;
    bytes32 preTxState;
    bytes32 userOpHash;
}

struct FlopsCommitment {
    FlopsData data;
    bytes signature;
}
