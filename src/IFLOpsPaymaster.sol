// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

interface IFlopsPaymaster {
    function bundleBroken() external view returns (bool);
    function bundleBroken(uint256 bundleNumber) external view returns (bool);
    function currentBundleNumber() external view returns (uint256);
    function finalizeCurrentBundle() external;
    function setFactory(address factory_) external;
    function factory() external view returns (address);
    function nextRollingHash(PackedUserOperation calldata userOp) external view returns (bytes32);
}
