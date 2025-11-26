// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseAccount} from "lib/account-abstraction/contracts/core/BaseAccount.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "lib/account-abstraction/contracts/core/Helpers.sol";
import {IFlopsPaymaster} from "./IFlopsPaymaster.sol";

/**
 * @title FlopsAccount
 * @notice ERC-4337 smart contract account with FLOps protocol integration
 * @dev This account enforces FLOps guardrails by checking with the paymaster
 *      before executing transactions. If the current block is broken, execution
 *      is prevented to maintain deterministic ordering guarantees.
 *
 *      Security model:
 *      - Owner address controls the account via ECDSA signatures
 *      - Only EntryPoint can execute transactions
 *      - Factory reference is immutable after construction
 *      - Paymaster reference enforces FLOps protocol rules
 *
 */
contract FlopsAccount is BaseAccount {
    // ============ Custom Errors ============

    /// @notice Thrown when a zero address is provided where not allowed
    error ZeroAddress();

    /// @notice Thrown when attempting to execute in a broken block
    error BlockBroken();

    /// @notice Thrown when signature validation fails
    error InvalidSignature();

    // ============ Constants ============

    /// @notice The canonical ERC-4337 EntryPoint address
    address public constant ENTRY_POINT_ADDRESS = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;

    // ============ State Variables ============

    /// @notice The owner address that can authorize operations
    address public owner;

    /// @notice The factory that deployed this account (immutable after construction)
    address public immutable factory;

    /// @notice The FLOps paymaster that enforces protocol rules
    IFlopsPaymaster public flopsPaymaster;

    // ============ Constructor ============

    /**
     * @notice Constructs a new FlopsAccount
     * @param _owner The owner address for this account
     * @param _factory The factory that deployed this account
     * @param _paymaster The FLOps paymaster address
     * @dev All parameters must be non-zero addresses
     */
    constructor(address _owner, address _factory, address _paymaster) {
        if (_owner == address(0)) revert ZeroAddress();
        if (_factory == address(0)) revert ZeroAddress();
        if (_paymaster == address(0)) revert ZeroAddress();

        owner = _owner;
        factory = _factory;
        flopsPaymaster = IFlopsPaymaster(_paymaster);
    }

    /// @notice Allows the account to receive ETH
    receive() external payable {}

    // ============ Public/External Functions ============

    /**
     * @notice Returns the EntryPoint contract
     * @return The IEntryPoint interface for the canonical EntryPoint
     */
    function entryPoint() public pure override returns (IEntryPoint) {
        return IEntryPoint(ENTRY_POINT_ADDRESS);
    }

    // ============ Internal Functions ============

    /**
     * @notice Validates the signature on a user operation
     * @param userOp The user operation to validate
     * @param userOpHash The hash of the user operation
     * @return validationData 0 for success, SIG_VALIDATION_FAILED for failure
     * @dev Uses ECDSA signature validation. The owner must have signed the userOpHash.
     *      Gas optimization: Uses tryRecover to avoid revert in signature validation.
     */
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        override
        returns (uint256)
    {
        // Gas optimization: Use tryRecover instead of recover to avoid revert
        (address recovered, ECDSA.RecoverError error,) = ECDSA.tryRecover(userOpHash, userOp.signature);

        if (error != ECDSA.RecoverError.NoError || recovered != owner) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    /**
     * @notice Enforces requirements before executing a transaction
     * @dev Overrides BaseAccount to add FLOps protocol guardrail.
     *      Checks two conditions:
     *      1. Call must come from EntryPoint (standard ERC-4337 requirement)
     *      2. Current block must not be broken (FLOps protocol requirement)
     */
    function _requireForExecute() internal view override {
        _requireFromEntryPoint();
        // FLOps guardrail: once current block is broken, no FlopsAccount should execute
        if (flopsPaymaster.blockBroken()) {
            revert BlockBroken();
        }
    }

    /**
     * @notice Validates the nonce of a user operation
     * @param nonce The nonce to validate
     * @dev FLOps currently uses EntryPoint's default nonce management.
     *      This function is left empty as nonce uniqueness is enforced by EntryPoint.
     *      Future enhancements could add custom nonce validation logic here.
     */
    function _validateNonce(uint256 nonce) internal view override {
        // Nonce validation handled by EntryPoint
        // Custom nonce logic can be added here if needed
    }
}
