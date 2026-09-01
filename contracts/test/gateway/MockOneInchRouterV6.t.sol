// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {Test} from "forge-std/Test.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockOneInchRouterV6} from "src/testnet/MockOneInchRouterV6.sol";
import {MockERC20} from "test/helpers/Mocks.sol";

contract MockOneInchRouterV6Test is Test {
    MockOneInchRouterV6 internal router;
    MockERC20 internal inputToken;
    MockERC20 internal outputToken;
    address internal receiver = makeAddr("receiver");
    address internal nonOwner = makeAddr("nonOwner");

    function setUp() public {
        router = new MockOneInchRouterV6(address(this));
        inputToken = new MockERC20();
        outputToken = new MockERC20();
        router.setPairRate(address(inputToken), address(outputToken), 2, 1);
        inputToken.mint(address(this), 100 ether);
        outputToken.mint(address(router), 1_000 ether);
        inputToken.approve(address(router), type(uint256).max);
    }

    function test_quote_usesConfiguredRawUnitRate() public view {
        // Arrange - configure a 2:1 raw-unit pair in setUp.
        uint256 amount = 3 ether;

        // Act - quote the exact input amount.
        uint256 amountOut = router.quote(address(inputToken), address(outputToken), amount);

        // Assert - apply the configured numerator and denominator exactly.
        assertEq(amountOut, 6 ether);
    }

    function test_swap_usesAggregationRouterV6Selector() public pure {
        // Arrange - use the production allowlisted selector.
        bytes4 expected = 0x07ed2379;

        // Act - read the mock Router's compiled selector.
        bytes4 actual = MockOneInchRouterV6.swap.selector;

        // Assert - keep ABI compatibility with AggregationRouterV6.
        assertEq(actual, expected);
    }

    function test_swap_transfersExactInputAndQuotedOutput() public {
        // Arrange - build canonical V6 swap arguments.
        MockOneInchRouterV6.SwapDescription memory desc = MockOneInchRouterV6.SwapDescription({
            srcToken: inputToken,
            dstToken: outputToken,
            srcReceiver: payable(address(router)),
            dstReceiver: payable(receiver),
            amount: 3 ether,
            minReturnAmount: 6 ether,
            flags: 0
        });

        // Act - execute the inventory-backed swap.
        (uint256 returnAmount, uint256 spentAmount) = router.swap(address(router), desc, hex"01");

        // Assert - consume all input and deliver the quoted output.
        assertEq(spentAmount, 3 ether);
        assertEq(returnAmount, 6 ether);
        assertEq(inputToken.balanceOf(address(router)), 3 ether);
        assertEq(outputToken.balanceOf(receiver), 6 ether);
    }

    function test_revertWhen_minimumReturnExceedsQuote() public {
        // Arrange - require one unit more than the configured rate returns.
        MockOneInchRouterV6.SwapDescription memory desc = MockOneInchRouterV6.SwapDescription({
            srcToken: inputToken,
            dstToken: outputToken,
            srcReceiver: payable(address(router)),
            dstReceiver: payable(receiver),
            amount: 3 ether,
            minReturnAmount: 6 ether + 1,
            flags: 0
        });

        // Act - expect the router to reject the swap.
        vm.expectRevert(
            abi.encodeWithSelector(MockOneInchRouterV6.InsufficientReturnAmount.selector, 6 ether, 6 ether + 1)
        );
        router.swap(address(router), desc, hex"01");

        // Assert - the reverted call moved no tokens.
        assertEq(inputToken.balanceOf(address(router)), 0);
        assertEq(outputToken.balanceOf(receiver), 0);
    }

    function test_revertWhen_pairIsNotConfigured() public {
        // Arrange - remove the only configured pair.
        router.removePair(address(inputToken), address(outputToken));

        // Act - quote the disabled pair.
        vm.expectRevert(
            abi.encodeWithSelector(
                MockOneInchRouterV6.PairNotConfigured.selector, address(inputToken), address(outputToken)
            )
        );
        router.quote(address(inputToken), address(outputToken), 1 ether);

        // Assert - the pair remains disabled.
        (, uint256 denominator) = router.pairRates(address(inputToken), address(outputToken));
        assertEq(denominator, 0);
    }

    function test_revertWhen_outputInventoryIsInsufficient() public {
        // Arrange - request more output than the Router holds.
        uint256 amount = 501 ether;

        // Act - quote the underfunded swap.
        vm.expectRevert(
            abi.encodeWithSelector(
                MockOneInchRouterV6.InsufficientInventory.selector, address(outputToken), 1_000 ether, 1_002 ether
            )
        );
        router.quote(address(inputToken), address(outputToken), amount);

        // Assert - quoting did not move any inventory.
        assertEq(outputToken.balanceOf(address(router)), 1_000 ether);
    }

    function test_revertWhen_swapAddressesAreInvalid() public {
        // Arrange - start from an otherwise valid exact-input swap.
        MockOneInchRouterV6.SwapDescription memory desc = _validDescription();

        // Act and Assert - reject each address field before any token movement.
        vm.expectRevert(MockOneInchRouterV6.InvalidSwap.selector);
        router.swap(address(0), desc, hex"01");

        desc.srcToken = IERC20(address(0));
        vm.expectRevert(MockOneInchRouterV6.InvalidSwap.selector);
        router.swap(address(router), desc, hex"01");
        desc.srcToken = inputToken;

        desc.dstToken = IERC20(address(0));
        vm.expectRevert(MockOneInchRouterV6.InvalidSwap.selector);
        router.swap(address(router), desc, hex"01");
        desc.dstToken = outputToken;

        desc.srcReceiver = payable(address(0));
        vm.expectRevert(MockOneInchRouterV6.InvalidSwap.selector);
        router.swap(address(router), desc, hex"01");
        desc.srcReceiver = payable(address(router));

        desc.dstReceiver = payable(address(0));
        vm.expectRevert(MockOneInchRouterV6.InvalidSwap.selector);
        router.swap(address(router), desc, hex"01");

        assertEq(inputToken.balanceOf(address(router)), 0);
        assertEq(outputToken.balanceOf(receiver), 0);
    }

    function test_revertWhen_swapMetadataIsInvalid() public {
        // Arrange - start from an otherwise valid exact-input swap.
        MockOneInchRouterV6.SwapDescription memory desc = _validDescription();
        vm.deal(address(this), 1 wei);

        // Act and Assert - reject ETH, flags, empty route data, and zero input.
        vm.expectRevert(MockOneInchRouterV6.InvalidSwap.selector);
        router.swap{value: 1 wei}(address(router), desc, hex"01");

        desc.flags = 1;
        vm.expectRevert(MockOneInchRouterV6.InvalidSwap.selector);
        router.swap(address(router), desc, hex"01");
        desc.flags = 0;

        vm.expectRevert(MockOneInchRouterV6.InvalidSwap.selector);
        router.swap(address(router), desc, hex"");

        desc.amount = 0;
        vm.expectRevert(MockOneInchRouterV6.InvalidSwap.selector);
        router.swap(address(router), desc, hex"01");

        assertEq(inputToken.balanceOf(address(router)), 0);
        assertEq(outputToken.balanceOf(receiver), 0);
    }

    function test_revertWhen_nonOwnerSetsPairRate() public {
        // Arrange - use an account without Router ownership.
        vm.prank(nonOwner);

        // Act - attempt to update a configured pair.
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, nonOwner));
        router.setPairRate(address(inputToken), address(outputToken), 3, 1);

        // Assert - preserve the owner-configured rate.
        (uint256 numerator, uint256 denominator) = router.pairRates(address(inputToken), address(outputToken));
        assertEq(numerator, 2);
        assertEq(denominator, 1);
    }

    function test_revertWhen_nonOwnerRemovesPair() public {
        // Arrange - use an account without Router ownership.
        vm.prank(nonOwner);

        // Act - attempt to disable a configured pair.
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, nonOwner));
        router.removePair(address(inputToken), address(outputToken));

        // Assert - preserve the owner-configured rate.
        (, uint256 denominator) = router.pairRates(address(inputToken), address(outputToken));
        assertEq(denominator, 1);
    }

    function test_revertWhen_nonOwnerWithdrawsInventory() public {
        // Arrange - use an account without Router ownership.
        vm.prank(nonOwner);

        // Act - attempt to withdraw Router inventory.
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, nonOwner));
        router.withdrawToken(outputToken, nonOwner, 1 ether);

        // Assert - preserve the complete output inventory.
        assertEq(outputToken.balanceOf(address(router)), 1_000 ether);
        assertEq(outputToken.balanceOf(nonOwner), 0);
    }

    function test_revertWhen_pairAddressesAreInvalid() public {
        // Arrange - use zero and identical token addresses.

        // Act and Assert - reject every invalid pair shape.
        vm.expectRevert(MockOneInchRouterV6.InvalidPair.selector);
        router.setPairRate(address(0), address(outputToken), 1, 1);

        vm.expectRevert(MockOneInchRouterV6.InvalidPair.selector);
        router.setPairRate(address(inputToken), address(0), 1, 1);

        vm.expectRevert(MockOneInchRouterV6.InvalidPair.selector);
        router.setPairRate(address(inputToken), address(inputToken), 1, 1);
    }

    function test_revertWhen_pairRateIsZero() public {
        // Arrange - use a valid pair with one zero rate component.

        // Act and Assert - reject zero numerator and denominator.
        vm.expectRevert(MockOneInchRouterV6.InvalidRate.selector);
        router.setPairRate(address(inputToken), address(outputToken), 0, 1);

        vm.expectRevert(MockOneInchRouterV6.InvalidRate.selector);
        router.setPairRate(address(inputToken), address(outputToken), 1, 0);
    }

    function _validDescription() internal view returns (MockOneInchRouterV6.SwapDescription memory) {
        return MockOneInchRouterV6.SwapDescription({
            srcToken: inputToken,
            dstToken: outputToken,
            srcReceiver: payable(address(router)),
            dstReceiver: payable(receiver),
            amount: 3 ether,
            minReturnAmount: 6 ether,
            flags: 0
        });
    }
}
