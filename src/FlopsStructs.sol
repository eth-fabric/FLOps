// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

struct BundleInfo {
    bool broken;
    bool finalized;
    bytes32 finalRollingHash;
}

struct FlopsData {
    uint256 bundleNumber;
    bytes32 preTxState;
    bytes32 userOpHash;
    bool endOfBundle;
}

struct FlopsCommitment {
    FlopsData data;
    bytes signature;
}
