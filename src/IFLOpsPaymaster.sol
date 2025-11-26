// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

interface IFlopsPaymaster {
    function blockBroken() external view returns (bool);
    function blockBroken(uint64 blockNumber) external view returns (bool);
    function setFactory(address factory_) external;
    function factory() external view returns (address);
    function nextRollingHash(PackedUserOperation calldata userOp) external view returns (bytes32);
}
