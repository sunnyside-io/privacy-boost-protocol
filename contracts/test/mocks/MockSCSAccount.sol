// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

/// @notice Test fixture mimicking the on-chain wire format that Startale SCS
///         Account on Soneium emits for ERC-1271 signatures:
///
///             sig (85 bytes) = bytes20(validator) || k1ECDSA(r||s||v)
///
///         The captured fixture uses the zero-address validator slot, which on
///         a real ERC-7579 modular account routes to the default ECDSA
///         validator module. This contract inlines the K1 ECDSA recover step
///         rather than reproducing the full module installation / pre-validation
///         hook / ERC-7739 stack — we are exercising the server's 1271 dispatch
///         path, not a faithful Nexus reproduction. Reject any sig that doesn't
///         match the captured wire format exactly.
///
///         A second responsibility — `execute` — lets the owner relay arbitrary
///         calls through this account so it can be `msg.sender` at the Pool /
///         AuthRegistry without an EntryPoint or bundler.
contract MockSCSAccount {
    address public immutable owner;

    error NotOwner();
    error ExecFailed(bytes ret);

    constructor(address _owner) {
        owner = _owner;
    }

    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        if (sig.length != 85) return 0xffffffff;
        if (bytes20(sig[0:20]) != bytes20(0)) return 0xffffffff;

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(add(sig.offset, 20))
            s := calldataload(add(sig.offset, 52))
            v := byte(0, calldataload(add(sig.offset, 84)))
        }
        if (v < 27) v += 27;
        address recovered = ecrecover(hash, v, r, s);
        if (recovered != address(0) && recovered == owner) return 0x1626ba7e;
        return 0xffffffff;
    }

    function execute(address target, uint256 value, bytes calldata data) external returns (bytes memory ret) {
        if (msg.sender != owner) revert NotOwner();
        bool ok;
        (ok, ret) = target.call{value: value}(data);
        if (!ok) revert ExecFailed(ret);
    }

    receive() external payable {}
}

contract MockSCSAccountFactory {
    event Deployed(address indexed wallet, address indexed owner);

    function deploy(address _owner) external returns (address wallet) {
        wallet = address(new MockSCSAccount(_owner));
        emit Deployed(wallet, _owner);
    }

    /// @notice CREATE2 deploy used by the EIP-6492 e2e flow. The wallet
    ///         address must be precomputable so the user can authenticate
    ///         (and the server can defer registration) before the wallet
    ///         exists on-chain. Idempotent: if the wallet is already
    ///         deployed at the predicted address, returns it without
    ///         redeploying — matches what the deployless 6492 validator
    ///         does inside its eth_call simulation.
    function deployCreate2(address _owner, bytes32 salt) external returns (address wallet) {
        wallet = getAddress(_owner, salt);
        if (wallet.code.length == 0) {
            wallet = address(new MockSCSAccount{salt: salt}(_owner));
            emit Deployed(wallet, _owner);
        }
    }

    /// @notice Returns the CREATE2 address `deployCreate2(_owner, salt)`
    ///         would land at. View function — reads `address(this)` (so
    ///         it cannot be `pure`) but never mutates state.
    function getAddress(address _owner, bytes32 salt) public view returns (address) {
        bytes memory initCode = abi.encodePacked(type(MockSCSAccount).creationCode, abi.encode(_owner));
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(initCode)));
        return address(uint160(uint256(hash)));
    }
}
