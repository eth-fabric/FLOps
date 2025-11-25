// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFlopsAccountFactory {
    function isFlopsAccount(address account) external view returns (bool);
}
