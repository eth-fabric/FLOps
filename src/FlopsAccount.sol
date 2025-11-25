// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseAccount} from "lib/account-abstraction/contracts/core/BaseAccount.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "account-abstraction/core/Helpers.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract FlopsAccount is BaseAccount {
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

    function _requireForExecute() internal view override {
        _requireFromEntryPoint();
        // todo check if bundle is broken at the paymaster
    }

    /**
     * Validate the nonce of the UserOperation.
     * This method may validate the nonce requirement of this account.
     * e.g.
     * To limit the nonce to use sequenced UserOps only (no "out of order" UserOps):
     *      `require(nonce < type(uint64).max)`
     * For a hypothetical account that *requires* the nonce to be out-of-order:
     *      `require(nonce & type(uint64).max == 0)`
     *
     * The actual nonce uniqueness is managed by the EntryPoint, and thus no other
     * action is needed by the account itself.
     *
     * @param nonce to validate
     *
     * solhint-disable-next-line no-empty-blocks
     */
    function _validateNonce(uint256 nonce) internal view override {
        // currently does nothing
    }
}

