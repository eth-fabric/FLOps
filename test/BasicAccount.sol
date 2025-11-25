// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseAccount} from "lib/account-abstraction/contracts/core/BaseAccount.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "account-abstraction/core/Helpers.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract BasicAccount is BaseAccount {
    address public constant ENTRY_POINT_ADDRESS = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }
    receive() external payable {}

    function entryPoint() public view override returns (IEntryPoint) {
        return IEntryPoint(ENTRY_POINT_ADDRESS);
    }

    // Simply validate ECDSA signature from owner
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        override
        returns (uint256)
    {
        if (owner != ECDSA.recover(userOpHash, userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }
}
