// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {FlopsAccount} from "./FlopsAccount.sol";
import {IFlopsAccountFactory} from "./interfaces/IFlopsAccountFactory.sol";

/**
 * @title FlopsAccountFactory
 * @notice Factory contract for deploying FlopsAccount instances
 * @dev This factory maintains a registry of deployed accounts and enforces
 *      that only registered accounts can use the FLOps paymaster.
 *
 *      Circular Dependency Resolution:
 *      This factory is referenced by FlopsPaymaster via setFactory() after deployment.
 *      The paymaster address must be set during factory construction.
 */
contract FlopsAccountFactory is IFlopsAccountFactory {
    // ============ State Variables ============

    /// @notice Mapping of account addresses to their registration status
    mapping(address => bool) public isFlopsAccount;

    /// @notice The FLOps paymaster address that all accounts will reference
    address public flopsPaymaster;

    // ============ Constructor ============

    /**
     * @notice Constructs the FlopsAccountFactory
     * @param _flopsPaymaster The FLOps paymaster address
     * @dev Paymaster address must be non-zero and is immutable after construction
     */
    constructor(address _flopsPaymaster) {
        if (_flopsPaymaster == address(0)) revert ZeroAddress();
        flopsPaymaster = _flopsPaymaster;
    }

    // ============ External Functions ============

    /**
     * @notice Creates a new FlopsAccount
     * @param owner The owner address for the new account
     * @return account The address of the newly created account
     * @dev The account is automatically registered in the isFlopsAccount mapping.
     *      Owner address must be non-zero to prevent accidental loss of funds.
     */
    function createAccount(address owner) external returns (address account) {
        if (owner == address(0)) revert ZeroAddress();

        FlopsAccount newAccount = new FlopsAccount(owner, address(this), flopsPaymaster);
        account = address(newAccount);
        isFlopsAccount[account] = true;
        emit AccountCreated(account, owner);
    }
}

