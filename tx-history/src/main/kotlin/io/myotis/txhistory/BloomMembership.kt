package io.myotis.txhistory

import com.jaeckel.trueblocks.Bloom
import org.kethereum.model.Address

/**
 * Bloom membership for a lowercase 0x-address. trueblocks-kotlin's matcher takes a
 * kethereum [Address]; the explicit `kethereum-model` dependency makes this a plain
 * compile-time call (the old DebugCommands built the Address reflectively to avoid
 * that dependency — no longer necessary now the TrueBlocks code lives in one module).
 *
 * A bloom answers "possibly present" — false positives are expected and resolved by
 * fetching the chunk's real index; false negatives cannot happen.
 */
fun Bloom.containsAddress(lowercaseHexAddress: String): Boolean =
    isMemberBytes(Address(lowercaseHexAddress))
