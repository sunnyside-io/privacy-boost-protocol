// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

/// @notice Test fixture for the ERC-7739 ("defensive rehashing") signature
///         path. Mimics the Solady-derived generic-wrap pattern used by
///         ERC-7579 / Nexus / Startale validators: the wallet does NOT
///         introspect the dapp's typed data; instead it expects the caller's
///         `bytes32 hash` to equal `keccak256(0x1901 || appSep || contentsHash)`
///         where `appSep` and `contentsHash` are carried in the signature
///         appendix.
///
///         Layout enforced here:
///
///             sig = innerECDSA(65)
///                || APP_DOMAIN_SEPARATOR(32)
///                || contentsHash(32)
///                || contentsDescription(N)
///                || uint16(N)
///
///         The inner ECDSA must recover to `owner` against the wallet's
///         OWN TypedDataSign digest:
///
///             walletDigest = keccak256(0x1901 || walletDomainSep
///                                       || keccak256(TYPED_DATA_SIGN_TYPEHASH,
///                                                    contentsHash,
///                                                    keccak(NAME),
///                                                    keccak(VERSION),
///                                                    chainId,
///                                                    address(this)))
///
///         The typestring is hardcoded as `Contents(bytes32 stuff)` so the
///         test fixture's behavior is deterministic. A faithful Solady
///         implementation would compute the typehash from the appendix's
///         contentsDescription bytes; that's not needed to exercise the
///         server's `verifyEIP712AuthSig` rewrap or AuthRegistry's
///         `_verifyOwnerSig` rewrap, which is the only thing this fixture
///         exists to test.
contract MockERC7739Account {
    address public immutable owner;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev Solady-style TypedDataSign typestring. The trailing
    ///      `Contents(bytes32 stuff)` repetition follows EIP-712's nested
    ///      struct encoding rule (referenced structs appended in alphabetical
    ///      order). Pinned constant rather than dynamic so the typehash is
    ///      a compile-time value and the fixture is auditable by inspection.
    bytes32 private constant TYPED_DATA_SIGN_TYPEHASH = keccak256(
        "TypedDataSign(Contents contents,string name,string version,uint256 chainId,address verifyingContract)Contents(bytes32 stuff)"
    );

    string private constant NAME = "MockERC7739Account";
    string private constant VERSION = "1";

    /// @dev keccak(EXPECTED_CONTENTS_TYPE) cached so the appendix check is
    ///      a single keccak vs string comparison. Any sig whose appendix
    ///      carries a different contents type is rejected — a real wallet
    ///      would adapt to the appendix's type bytes; we don't need that
    ///      flexibility for the test fixture.
    bytes private constant EXPECTED_CONTENTS_TYPE = "Contents(bytes32 stuff)";

    error NotOwner();
    error ExecFailed(bytes ret);

    constructor(address _owner) {
        owner = _owner;
    }

    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        // Minimum length: 65 (inner) + 32 (appSep) + 32 (contentsHash) +
        // 1 (smallest type description) + 2 (uint16 trailer) = 132.
        if (sig.length < 132) return 0xffffffff;

        // The uint16(N) trailer is the LAST 2 bytes, big-endian.
        uint256 n = (uint256(uint8(sig[sig.length - 2])) << 8) | uint256(uint8(sig[sig.length - 1]));
        if (n == 0 || n > 256) return 0xffffffff;
        // Need room for inner sig (>=65 bytes) before the 32+32+n+2 appendix.
        if (sig.length < 66 + n + 65) return 0xffffffff;

        uint256 appStart = sig.length - 66 - n;
        bytes32 appSep = bytes32(sig[appStart:appStart + 32]);
        bytes32 contentsHash = bytes32(sig[appStart + 32:appStart + 64]);
        bytes calldata contentsType = sig[appStart + 64:appStart + 64 + n];
        bytes calldata innerSig = sig[0:65];

        // Sanity-check: this mock only understands the hardcoded type.
        if (keccak256(contentsType) != keccak256(EXPECTED_CONTENTS_TYPE)) return 0xffffffff;

        // 1. The caller (server-side rewrap or AuthRegistry._verifyOwnerSig
        //    rewrap) must produce a hash that equals
        //    keccak(0x1901 || appSep || contentsHash). A foreign appSep on
        //    the appendix that doesn't match the caller's expected app
        //    domain is the failure mode the test's negative case relies
        //    on.
        bytes32 expectedDappHash = keccak256(abi.encodePacked(hex"1901", appSep, contentsHash));
        if (hash != expectedDappHash) return 0xffffffff;

        // 2. The wallet recovers the signer from ITS OWN TypedDataSign
        //    digest — not the dapp's. The wallet domain is independent of
        //    the dapp's (different name, different verifyingContract).
        bytes32 walletStructHash = keccak256(
            abi.encode(
                TYPED_DATA_SIGN_TYPEHASH,
                contentsHash,
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
        bytes32 walletDigest = keccak256(abi.encodePacked(hex"1901", _domainSeparator(), walletStructHash));

        // 3. Recover from inner ECDSA.
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(innerSig.offset)
            s := calldataload(add(innerSig.offset, 32))
            v := byte(0, calldataload(add(innerSig.offset, 64)))
        }
        if (v < 27) v += 27;
        address recovered = ecrecover(walletDigest, v, r, s);
        if (recovered != address(0) && recovered == owner) return 0x1626ba7e;
        return 0xffffffff;
    }

    /// @notice Owner-relayed call so this account can be `msg.sender` at
    ///         the Pool / AuthRegistry without an EntryPoint or bundler.
    ///         Same shape as MockSCSAccount.execute so the test driver's
    ///         scwExecute() helper is reusable.
    function execute(address target, uint256 value, bytes calldata data) external returns (bytes memory ret) {
        if (msg.sender != owner) revert NotOwner();
        bool ok;
        (ok, ret) = target.call{value: value}(data);
        if (!ok) revert ExecFailed(ret);
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(NAME)), keccak256(bytes(VERSION)), block.chainid, address(this))
        );
    }

    receive() external payable {}
}

contract MockERC7739AccountFactory {
    event Deployed(address indexed wallet, address indexed owner);

    function deploy(address _owner) external returns (address wallet) {
        wallet = address(new MockERC7739Account(_owner));
        emit Deployed(wallet, _owner);
    }

    /// @notice CREATE2 deploy used by the EIP-6492 + 7739 combo flow.
    ///         Idempotent: if the wallet is already deployed at the
    ///         predicted address, returns it without redeploying — matches
    ///         what the deployless 6492 validator does inside its eth_call
    ///         simulation.
    function deployCreate2(address _owner, bytes32 salt) external returns (address wallet) {
        wallet = getAddress(_owner, salt);
        if (wallet.code.length == 0) {
            wallet = address(new MockERC7739Account{salt: salt}(_owner));
            emit Deployed(wallet, _owner);
        }
    }

    function getAddress(address _owner, bytes32 salt) public view returns (address) {
        bytes memory initCode = abi.encodePacked(type(MockERC7739Account).creationCode, abi.encode(_owner));
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(initCode)));
        return address(uint160(uint256(hash)));
    }
}
