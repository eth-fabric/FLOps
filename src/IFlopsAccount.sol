// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IFlopsPaymaster} from "./IFlopsPaymaster.sol";

/**
 * @title IFlopsAccount
 * @notice Interface for FLOps smart contract accounts
 * @dev Defines the public API for FlopsAccount, including errors and view functions
 */
interface IFlopsAccount {
    // ============ Custom Errors ============

    /// @notice Thrown when a zero address is provided where not allowed
    error ZeroAddress();

    /// @notice Thrown when attempting to execute in a broken block
    error BlockBroken();

    /// @notice Thrown when signature validation fails
    error InvalidSignature();

    // ============ View Functions ============

    /**
     * @notice Returns the EntryPoint contract
     * @return The IEntryPoint interface for the canonical EntryPoint
     */
    function entryPoint() external view returns (IEntryPoint);

    /**
     * @notice Returns the owner address that can authorize operations
     * @return The owner address
     */
    function owner() external view returns (address);

    /**
     * @notice Returns the factory that deployed this account
     * @return The factory address
     */
    function factory() external view returns (address);

    /**
     * @notice Returns the FLOps paymaster that enforces protocol rules
     * @return The FlopsPaymaster interface
     */
    function flopsPaymaster() external view returns (IFlopsPaymaster);
}




