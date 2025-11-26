// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IFlopsAccountFactory
 * @notice Interface for the FLOps account factory contract
 * @dev Defines the public API for creating and validating FlopsAccounts
 */
interface IFlopsAccountFactory {
    // ============ Events ============

    /**
     * @notice Emitted when a new FlopsAccount is created
     * @param account The address of the newly created account
     * @param owner The owner address of the account
     */
    event AccountCreated(address indexed account, address indexed owner);

    // ============ View Functions ============

    /**
     * @notice Checks if an address is a registered FlopsAccount
     * @param account The address to check
     * @return True if the address is a registered FlopsAccount
     */
    function isFlopsAccount(address account) external view returns (bool);

    /**
     * @notice Returns the FLOps paymaster address
     * @return The paymaster address that all accounts reference
     */
    function flopsPaymaster() external view returns (address);

    // ============ External Functions ============

    /**
     * @notice Creates a new FlopsAccount
     * @param owner The owner address for the new account
     * @return account The address of the newly created account
     */
    function createAccount(address owner) external returns (address account);
}
