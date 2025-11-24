// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {BasePaymaster} from "lib/account-abstraction/contracts/core/BasePaymaster.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

import {IFLOpsPaymaster} from "./IFLOpsPaymaster.sol";

contract FLOpsPaymaster is BasePaymaster, IFLOpsPaymaster {
    bool public bundleBroken;

    address public atomicEntryPoint;

    constructor(IEntryPoint _entryPoint, address _owner) BasePaymaster(_entryPoint, _owner) {}

    modifier _requireFromAtomicEntryPoint() {
        require(msg.sender == address(atomicEntryPoint), "FLOpsPaymaster: Not from atomic entrypoint");
        _;
    }

    function setAtomicEntryPoint(address _atomicEntryPoint) external onlyOwner {
        atomicEntryPoint = _atomicEntryPoint;
    }

    function resetBundle() external {
        bundleBroken = false;
    }

    /**
     * Validate a user operation.
     * @param userOp     - The user operation.
     * @param userOpHash - The hash of the user operation.
     * @param maxCost    - The maximum cost of the user operation.
     */
    function _validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        internal
        override
        returns (bytes memory context, uint256 validationData)
    {
        // todo update rolling hashes
        return (context, validationData);
    }

    /**
     * Post-operation handler.
     * (verified to be called only through the entryPoint)
     * @dev If subclass returns a non-empty context from validatePaymasterUserOp,
     *      it must also implement this method.
     * @param mode          - Enum with the following options:
     *                        opSucceeded - User operation succeeded.
     *                        opReverted  - User op reverted. The paymaster still has to pay for gas.
     *                        postOpReverted - never passed in a call to postOp().
     * @param context       - The context value returned by validatePaymasterUserOp
     * @param actualGasCost - Actual cost of gas used so far (without this postOp call).
     * @param actualUserOpFeePerGas - the gas price this UserOp pays. This value is based on the UserOp's maxFeePerGas
     *                        and maxPriorityFee (and basefee)
     *                        It is not the same as tx.gasprice, which is what the bundler pays.
     */
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        internal
        override
    {
        if (mode == PostOpMode.opReverted) {
            bundleBroken = true;
        }

        // todo
    }
}
