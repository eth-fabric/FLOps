// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IEntryPoint, PackedUserOperation} from "lib/openzeppelin-contracts/contracts/interfaces/draft-IERC4337.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import {IFLOpsPaymaster} from "./IFLOpsPaymaster.sol";

contract AtomicEntryPoint is ReentrancyGuardTransient {
    IEntryPoint public immutable entryPoint;
    IFLOpsPaymaster public immutable flops;

    constructor(address _entryPoint, address _flopsPaymaster) {
        entryPoint = IEntryPoint(_entryPoint);
        flops = IFLOpsPaymaster(_flopsPaymaster);
    }

    function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) external nonReentrant {
        // Start a new atomic bundle
        flops.resetBundle();

        // Execute the bundle
        entryPoint.handleOps(ops, beneficiary);

        // After EP finishes, inspect FLOps state
        // Revert if any of the user operations reverted
        if (flops.bundleBroken()) {
            revert("Atomic bundle reverted");
        }
    }
}
