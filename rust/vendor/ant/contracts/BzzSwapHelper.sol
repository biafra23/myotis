// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Minimal interfaces for the two contracts the helper touches.
interface IWXDAI {
    function deposit() external payable;
    function transfer(address to, uint256 value) external returns (bool);
}

interface IUniswapV3Pool {
    function swap(
        address recipient,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        bytes calldata data
    ) external returns (int256 amount0, int256 amount1);
}

/// Stateless, admin-less helper that swaps native xDAI into xBZZ in the
/// SushiSwap V3 BZZ/WXDAI 0.3% pool on Gnosis and delivers the xBZZ to
/// `recipient` in a single transaction. AntDrive's light node calls this
/// so users only ever have to send plain xDAI to their account — the node
/// wraps it, swaps it, and buys the storage batch itself.
///
/// The contract holds no funds between calls and has no owner. An EOA
/// can't call `pool.swap()` directly because the pool pays via a
/// callback only a contract can implement; this is that contract.
///
/// Addresses are baked in so the creation bytecode is constant, which in
/// turn makes the CREATE2 deployment address deterministic.
contract BzzSwapHelper {
    /// Wrapped xDAI (the pool's token1, 18 decimals).
    address internal constant WXDAI = 0xe91D153E0b41518A2Ce8Dd3D7944Fa863463a97d;
    /// SushiSwap V3 BZZ/WXDAI 0.3% pool. token0 = xBZZ, token1 = WXDAI.
    address internal constant POOL = 0x7583b9C573FA4FB5Ea21C83454939c4Cf6aacBc3;

    /// We pay token1 (WXDAI) and receive token0 (xBZZ), i.e. one→zero is
    /// false, so the price limit is the *upper* bound of the valid range:
    /// `TickMath.MAX_SQRT_RATIO - 1`.
    uint160 internal constant MAX_SQRT_RATIO_MINUS_ONE =
        1461446703485210103287273052203988822378723970342 - 1;

    /// Swap every wei of attached xDAI for xBZZ and send the xBZZ to
    /// `recipient`. Reverts unless at least `amountOutMin` xBZZ comes out,
    /// which is the caller's slippage guard.
    function swapXdaiForBzz(address recipient, uint256 amountOutMin)
        external
        payable
        returns (uint256 bzzOut)
    {
        require(msg.value > 0, "no xdai");
        IWXDAI(WXDAI).deposit{value: msg.value}();

        // amountSpecified > 0 ⇒ exact input of the input token (WXDAI).
        (int256 amount0, ) = IUniswapV3Pool(POOL).swap(
            recipient,
            false,
            int256(msg.value),
            MAX_SQRT_RATIO_MINUS_ONE,
            ""
        );

        // token0 (xBZZ) leaves the pool, so its delta is negative.
        bzzOut = uint256(-amount0);
        require(bzzOut >= amountOutMin, "slippage");
    }

    /// Uniswap V3 swap callback: pay the pool the WXDAI we owe.
    function uniswapV3SwapCallback(
        int256,
        int256 amount1Delta,
        bytes calldata
    ) external {
        require(msg.sender == POOL, "bad caller");
        require(amount1Delta > 0, "no debt");
        IWXDAI(WXDAI).transfer(POOL, uint256(amount1Delta));
    }
}
