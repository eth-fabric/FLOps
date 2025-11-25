// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFlopsPaymaster {
    function resetBundle() external;
    function bundleBroken() external view returns (bool);
}
