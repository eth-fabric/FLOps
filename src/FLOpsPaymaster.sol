// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {BasePaymaster} from "lib/account-abstraction/contracts/core/BasePaymaster.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UserOperationLib} from "lib/account-abstraction/contracts/core/UserOperationLib.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {IFlopsPaymaster} from "./IFlopsPaymaster.sol";
import {IFlopsAccountFactory} from "./IFlopsAccountFactory.sol";
import {BlockState, FlopsData, FlopsCommitment} from "./FlopsStructs.sol";

/**
 * @title FlopsPaymaster
 * @notice Paymaster implementation for the FLOps protocol that enforces deterministic transaction ordering
 * @dev This paymaster validates that transactions execute in the exact order committed by approved bundlers.
 *      It maintains a rolling hash per block to ensure transaction ordering integrity.
 *
 *      Circular Dependency Resolution:
 *      FlopsPaymaster references FlopsAccountFactory via setFactory() after deployment.
 *      This two-step initialization is necessary because both contracts need to reference each other.
 */
contract FlopsPaymaster is BasePaymaster, IFlopsPaymaster {
    // ============ Custom Errors ============

    /// @notice Thrown when a zero address is provided where not allowed
    error ZeroAddress();

    /// @notice Thrown when bundler array is empty during construction
    error EmptyBundlerArray();

    /// @notice Thrown when factory is not set
    error FactoryNotSet();

    // ============ Events ============

    /// @notice Emitted when a block's execution script is broken
    /// @param blockNumber The block number that was broken
    /// @param userOpHash The hash of the user operation that broke the block
    event BlockBroken(uint64 indexed blockNumber, bytes32 userOpHash);

    /// @notice Emitted when a bundler is approved
    /// @param bundler The address of the approved bundler
    event BundlerApproved(address indexed bundler);

    /// @notice Emitted when a bundler is revoked
    /// @param bundler The address of the revoked bundler
    event BundlerRevoked(address indexed bundler);

    /// @notice Emitted when the factory address is updated
    /// @param oldFactory The previous factory address
    /// @param newFactory The new factory address
    event FactoryUpdated(address indexed oldFactory, address indexed newFactory);

    // ============ State Variables ============

    /// @notice Mapping of approved bundler addresses
    mapping(address => bool) public approvedBundlers;

    /// @notice Mapping of block numbers to their state (broken status and rolling hash)
    mapping(uint64 => BlockState) public blocks;

    /// @notice Reference to the FlopsAccountFactory for validating account registration
    IFlopsAccountFactory private _factory;

    // ============ Constructor ============

    /**
     * @notice Constructs the FlopsPaymaster
     * @param _entryPoint The ERC-4337 EntryPoint contract
     * @param _owner The owner address for this paymaster
     * @param bundlers Array of approved bundler addresses
     * @dev Factory must be set separately via setFactory() after deployment
     */
    constructor(IEntryPoint _entryPoint, address _owner, address[] memory bundlers) BasePaymaster(_entryPoint, _owner) {
        if (_owner == address(0)) revert ZeroAddress();
        if (bundlers.length == 0) revert EmptyBundlerArray();

        for (uint256 i = 0; i < bundlers.length; i++) {
            if (bundlers[i] == address(0)) revert ZeroAddress();
            approvedBundlers[bundlers[i]] = true;
            emit BundlerApproved(bundlers[i]);
        }
    }

    // ============ Internal Functions ============

    /**
     * @notice Validates a user operation according to FLOps protocol rules
     * @param userOp The user operation to validate
     * @param userOpHash The hash of the user operation (cached for gas optimization)
     * @param maxCost The maximum gas cost of the operation
     * @return context Empty bytes (no postOp context needed for FLOps)
     * @return validationData Always returns 0 (validation success/failure indicated by block.broken state)
     * @dev This function enforces four critical FLOps guardrails:
     *      1. Block number must match current block
     *      2. Pre-transaction state (rolling hash) must match
     *      3. Bundler signature must be valid and from approved bundler
     *      4. Sender must be a registered FlopsAccount
     *      Any violation marks the block as broken and prevents execution
     */
    function _validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        internal
        override
        returns (bytes memory context, uint256 validationData)
    {
        uint64 blockNumber = uint64(block.number);

        bytes calldata paymasterSignature = UserOperationLib.getPaymasterSignature(userOp.paymasterAndData);
        FlopsCommitment memory commitment = abi.decode(paymasterSignature, (FlopsCommitment));
        FlopsData memory d = commitment.data;

        // FLOps guardrail #1: Operation must execute in the block it was committed for
        if (d.blockNumber != blockNumber) {
            blocks[blockNumber].broken = true;
            emit BlockBroken(blockNumber, d.userOpHash);
            return ("", 0);
        }

        BlockState storage blockState = blocks[blockNumber];
        bool broken = false;

        // FLOps guardrail #2: Verify pre-transaction state matches rolling hash
        if (d.preTxState != blockState.rollingHash) broken = true;

        // FLOps guardrail #3: Verify bundler signature
        if (!_verifyBundlerSignature(commitment, userOpHash)) broken = true;

        // FLOps guardrail #4: Verify sender is a registered FlopsAccount
        if (address(_factory) == address(0)) revert FactoryNotSet();
        if (!_factory.isFlopsAccount(userOp.sender)) broken = true;

        if (broken) {
            // FLOps violation detected during validation
            blockState.broken = true;
            emit BlockBroken(blockNumber, d.userOpHash);

            return ("", 0);
        }

        // Happy path: advance rolling hash for this block
        blockState.rollingHash = keccak256(abi.encode(blockState.rollingHash, d.userOpHash));

        return ("", 0);
    }

    /**
     * @notice Post-operation handler called after user operation execution
     * @param mode Execution result: opSucceeded or opReverted
     * @param context Empty context from validatePaymasterUserOp
     * @param actualGasCost Actual gas cost incurred
     * @param actualUserOpFeePerGas Gas price for this operation
     * @dev FLOps currently returns empty context, so this is only called when EntryPoint
     *      explicitly invokes it. If execution reverts, the block is marked as broken to
     *      maintain deterministic execution guarantees.
     *      Note: userOpHash is not tracked in context as it's not critical for postOp logic.
     */
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        internal
        override
    {
        // FLOps guardrail: if the transaction reverted, mark the block as broken
        // This guarantees deterministic execution outcomes
        if (mode != PostOpMode.opSucceeded) {
            uint64 blockNumber = uint64(block.number);
            blocks[blockNumber].broken = true;
            // userOpHash not available in postOp context for FLOps (empty context returned)
            emit BlockBroken(blockNumber, bytes32(0));
        }
        // Future enhancement: Add billing or accounting logic here
    }

    /**
     * @notice Internal helper to verify bundler signature with cached data
     * @param commitment The FlopsCommitment containing data and signature
     * @param userOpHash A trusted user operation hash
     * @return True if signature is valid and from an approved bundler
     * @dev Reuses already-computed values for gas optimization
     */
    function _verifyBundlerSignature(FlopsCommitment memory commitment, bytes32 userOpHash)
        internal
        view
        returns (bool)
    {
        // Verify the committed userOpHash matches the computed userOpHash
        if (commitment.data.userOpHash != userOpHash) return false;

        // Compute the commitment hash
        bytes32 commitmentHash = _computeBundlerCommitHash(commitment.data);

        // Verify the signer is an approved bundler
        address recovered = ECDSA.recover(commitmentHash, commitment.signature);
        return approvedBundlers[recovered];
    }

    /**
     * @notice Internal helper to compute bundler commit hash
     * @param data The FlopsData to hash
     * @return The EIP-191 signed message hash
     */
    function _computeBundlerCommitHash(FlopsData memory data) internal pure returns (bytes32) {
        bytes32 digest = keccak256(abi.encode(data));
        return MessageHashUtils.toEthSignedMessageHash(digest);
    }

    // ============ Public/External View Functions ============

    /**
     * @notice Computes what the rolling hash would be after including a user operation
     * @param userOp The user operation to simulate including
     * @return The next rolling hash value
     * @dev Useful for bundlers to compute the correct preTxState for subsequent operations
     */
    function nextRollingHash(PackedUserOperation calldata userOp) public view returns (bytes32) {
        uint64 blockNumber = uint64(block.number);
        bytes32 userOpHash = entryPoint().getUserOpHash(userOp);
        return keccak256(abi.encode(blocks[blockNumber].rollingHash, userOpHash));
    }

    /**
     * @notice Stateless function to compute the rolling hash for a user operation
     * @param rollingHash The current rolling hash
     * @param userOp The user operation to simulate including
     * @return The next rolling hash value
     */
    function nextRollingHash(bytes32 rollingHash, PackedUserOperation calldata userOp) public view returns (bytes32) {
        bytes32 userOpHash = entryPoint().getUserOpHash(userOp);
        return keccak256(abi.encode(rollingHash, userOpHash));
    }

    /**
     * @notice Verifies that a user operation has a valid bundler signature
     * @param userOp The user operation to verify
     * @return True if signature is valid and from an approved bundler
     * @dev This is a public wrapper around the internal verification function
     */
    function verifyBundlerSignature(PackedUserOperation calldata userOp) public view returns (bool) {
        // Retrieve the FlopsCommitment from the paymasterAndData
        bytes calldata flopsBytes = UserOperationLib.getPaymasterSignature(userOp.paymasterAndData);
        FlopsCommitment memory commitment = abi.decode(flopsBytes, (FlopsCommitment));

        bytes32 userOpHash = entryPoint().getUserOpHash(userOp);
        return _verifyBundlerSignature(commitment, userOpHash);
    }

    /**
     * @notice Checks if the current block is broken
     * @return True if current block's execution context is broken
     */
    function blockBroken() external view returns (bool) {
        return blocks[uint64(block.number)].broken;
    }

    /**
     * @notice Checks if a specific block is broken
     * @param blockNumber The block number to check
     * @return True if the specified block's execution context is broken
     * @dev Blocks remain broken permanently once marked
     */
    function blockBroken(uint64 blockNumber) external view returns (bool) {
        return blocks[blockNumber].broken;
    }

    /**
     * @notice Returns the factory address
     * @return The FlopsAccountFactory address
     */
    function factory() external view returns (address) {
        return address(_factory);
    }

    /**
     * @notice Computes the hash that bundlers must sign to commit to a transaction
     * @param data The FlopsData containing block number, pre-tx state, and userOpHash
     * @return The EIP-191 signed message hash
     * @dev Uses Ethereum signed message format for compatibility with standard wallets
     */
    function computeBundlerCommitHash(FlopsData memory data) external pure returns (bytes32) {
        return _computeBundlerCommitHash(data);
    }

    // ============ Owner Functions ============

    /**
     * @notice Sets the FlopsAccountFactory reference
     * @param factory_ The factory contract address
     * @dev Required for circular dependency resolution. Must be called after deployment.
     *      Zero address check ensures factory is properly initialized.
     */
    function setFactory(address factory_) external onlyOwner {
        if (factory_ == address(0)) revert ZeroAddress();
        address oldFactory = address(_factory);
        _factory = IFlopsAccountFactory(factory_);
        emit FactoryUpdated(oldFactory, factory_);
    }

    /**
     * @notice Approves a new bundler
     * @param bundler The bundler address to approve
     * @dev Only approved bundlers can sign FLOps commitments
     */
    function approveBundler(address bundler) external onlyOwner {
        if (bundler == address(0)) revert ZeroAddress();
        if (bundler == address(0)) revert ZeroAddress();
        approvedBundlers[bundler] = true;
        emit BundlerApproved(bundler);
    }

    /**
     * @notice Revokes a bundler's approval
     * @param bundler The bundler address to revoke
     * @dev Revoked bundlers can no longer sign valid FLOps commitments
     */
    function revokeBundler(address bundler) external onlyOwner {
        approvedBundlers[bundler] = false;
        emit BundlerRevoked(bundler);
    }
}
