// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {FlopsAccount} from "./FlopsAccount.sol";

contract FlopsAccountFactory {
    mapping(address => bool) public isFlopsAccount;

    event AccountCreated(address indexed account, address indexed owner);

    /**
     * Create a new FlopsAccount
     * @param owner The owner address for the new account
     * @return account The address of the newly created account
     */
    function createAccount(address owner) external returns (address account) {
        FlopsAccount newAccount = new FlopsAccount(owner, address(this));
        account = address(newAccount);
        isFlopsAccount[account] = true;
        emit AccountCreated(account, owner);
    }
}

