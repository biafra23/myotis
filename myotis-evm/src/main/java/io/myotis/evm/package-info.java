/**
 * myotis-evm — local EVM execution against SNAP-verified state.
 *
 * <p>The module exposes a narrow surface: callers ask for the result of a
 * view-style {@code eth_call} or a gas estimate, and the implementation
 * runs the EVM locally against state served on demand by SNAP proofs and
 * verified against the trusted {@code stateRoot}.
 *
 * <p>This package contains the public API. Internal subsystems live under
 * {@code abi}, {@code world}, {@code prefetch}, {@code ccipread}, and
 * {@code besu}.
 */
package io.myotis.evm;
