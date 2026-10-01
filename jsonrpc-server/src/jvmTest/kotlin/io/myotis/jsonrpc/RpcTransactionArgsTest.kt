package io.myotis.jsonrpc

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The eth_call / eth_estimateGas transaction object (#509): what the router accepts, what
 * it refuses, and the canonical JSON it hands the Rust engine — pinned here and
 * parsed by the same literal in `host::tests::parse_tx_request_reads_the_routers_canonical_form`,
 * the two halves of the cross-language golden.
 */
class RpcTransactionArgsTest {

    private fun parse(json: String): RpcTransactionArgs.Parsed =
        RpcTransactionArgs.parse(Json.parseToJsonElement(json).jsonObject)

    private fun valid(json: String): RpcTransactionArgs =
        (parse(json) as? RpcTransactionArgs.Parsed.Valid)?.tx
            ?: error("expected a valid object, got ${(parse(json) as RpcTransactionArgs.Parsed.Invalid).why}")

    private fun refusal(json: String): String =
        (parse(json) as? RpcTransactionArgs.Parsed.Invalid)?.why ?: error("expected a refusal for $json")

    /** The #509 request as ethers v6 sends it, normalized. The expected string
     *  is the golden the Rust parser test reads verbatim. */
    @Test fun canonicalFormOfAnEthersSetCodeRequest() {
        val tx = valid(
            """{"from":"0x1111111111111111111111111111111111111111",
                "to":"0x2222222222222222222222222222222222222222",
                "data":"0x3E12CC2E","value":"0x2386F26FC10000","nonce":"0x07","chainId":"0x1",
                "type":"0x4","maxFeePerGas":"0x3b9aca00","maxPriorityFeePerGas":"0x1",
                "accessList":[{"address":"0x3333333333333333333333333333333333333333",
                  "storageKeys":["0x0000000000000000000000000000000000000000000000000000000000000001"]}],
                "authorizationList":[{"address":"0x05ae73c5925d843864ae6f261f3175de2ebcd963",
                  "nonce":"0x0","chainId":"0x1","yParity":"0x1","r":"0x9a3b","s":"0x0c5d"}]}""",
        )
        assertEquals(CANONICAL, tx.json)
        assertEquals("10000000000000000", tx.valueWei)
        assertEquals("1000000000", tx.maxFeePerGasWei)
        assertEquals("1", tx.maxPriorityFeePerGasWei)
        assertEquals("1", tx.chainId)
        assertEquals(4, tx.type)
        assertTrue(tx.hasAuthorizationList && tx.hasAccessList && tx.hasExtendedFields)
    }

    @Test fun aPlainCallCarriesNoExtendedFields() {
        val tx = valid("""{"to":"0x2222222222222222222222222222222222222222","input":"0x01","accessList":[]}""")
        assertFalse(tx.hasExtendedFields, "an empty access list changes nothing")
        assertNull(tx.from)
        assertEquals("""{"to":"0x2222222222222222222222222222222222222222","input":"0x01","accessList":[]}""", tx.json)
        // `to` absent or null is contract creation.
        assertNull(valid("""{"to":null,"data":"0x6000"}""").to)
    }

    @Test fun aHugeGasReadsAsNoCapForTheTypedView() {
        val tx = valid("""{"gas":"0xffffffffffffffff"}""")
        assertEquals(Long.MAX_VALUE, tx.gas)
        assertTrue(tx.json.contains(""""gas":"0xffffffffffffffff""""), tx.json)
    }

    /** Each of these names no transaction that could exist, or one this node
     *  cannot simulate; the router refuses it rather than pick an answer. */
    @Test fun contradictionsAreRefusedWithAReason() {
        val to = """"to":"0x2222222222222222222222222222222222222222""""
        val auth = """{"address":"0x05ae73c5925d843864ae6f261f3175de2ebcd963","nonce":"0x0","chainId":"0x1","yParity":"0x0","r":"0x1","s":"0x1"}"""
        mapOf(
            """{$to,"type":"0x4"}""" to "requires an authorizationList",
            """{$to,"authorizationList":[]}""" to "must not be empty",
            """{"authorizationList":[$auth]}""" to "cannot create a contract",
            """{$to,"type":"0x2","authorizationList":[$auth]}""" to "requires transaction type 0x4",
            """{$to,"data":"0x01","input":"0x02"}""" to "not equal",
            """{$to,"gasPrice":"0x1","maxFeePerGas":"0x2"}""" to "both gasPrice",
            """{$to,"maxFeePerGas":"0x1","maxPriorityFeePerGas":"0x2"}""" to "greater than maxFeePerGas",
            // A missing cap is zero, as every engine reads it.
            """{$to,"maxPriorityFeePerGas":"0x1"}""" to "greater than maxFeePerGas (0)",
            """{$to,"type":"0x0","maxFeePerGas":"0x1"}""" to "require transaction type 0x2",
            """{$to,"type":"0x0","accessList":[{"address":"0x3333333333333333333333333333333333333333"}]}""" to "type 0x1 or later",
            """{$to,"type":"0x3"}""" to "blob transactions",
            """{$to,"blobVersionedHashes":["0x01"]}""" to "blob transactions",
            """{$to,"type":"0x7e"}""" to "unsupported transaction type",
            """{$to,"nonce":"0xffffffffffffffff"}""" to "EIP-2681",
            // Past the typed Long: refused with a reason, never thrown (#514 review).
            """{$to,"nonce":"0x8000000000000000"}""" to "above 0x7fffffffffffffff",
            """{$to,"nonce":"0xfffffffffffffffe"}""" to "above 0x7fffffffffffffff",
            """{"to":"0x1234"}""" to "'to' is not a 20-byte",
            """{$to,"gas":"0x10000000000000000"}""" to "exceeds 64 bits",
            """{$to,"authorizationList":[{"address":"0x05ae73c5925d843864ae6f261f3175de2ebcd963","nonce":"0x0","chainId":"0x1","r":"0x1","s":"0x1"}]}""" to "yParity",
            """{$to,"authorizationList":[{"address":"0x05ae73c5925d843864ae6f261f3175de2ebcd963","nonce":"0x0","chainId":"0x1","yParity":"0x0","v":"0x1","r":"0x1","s":"0x1"}]}""" to "disagree",
        ).forEach { (json, reason) ->
            val why = refusal(json)
            assertTrue(why.contains(reason), "expected '$reason' for $json, got '$why'")
        }
    }

    /** A quantity is a JSON string, as geth reads one: a JSON number is
     *  refused, never coerced. One parser serves eth_call and eth_estimateGas,
     *  so this holds for both (eth_call accepted `"value": 0` before #509). */
    @Test fun aQuantityMustBeAJsonString() {
        val to = """"to":"0x2222222222222222222222222222222222222222""""
        for (k in listOf("value", "gas", "gasPrice", "maxFeePerGas", "nonce")) {
            val why = refusal("""{$to,"$k":0}""")
            assertTrue(why.contains("'$k' is not a quantity"), "$k: $why")
        }
        assertEquals("0", valid("""{$to,"value":"0x0"}""").valueWei)
    }

    /** A legacy v of 27/28 is parity 0/1; left as 27 the tuple could not be
     *  recovered and the estimate would silently run without the delegation. */
    @Test fun aLegacyVIsNormalizedToYParity() {
        val auth = { extra: String ->
            """{"to":"0x2222222222222222222222222222222222222222","authorizationList":[{"address":"0x05ae73c5925d843864ae6f261f3175de2ebcd963","nonce":"0x0","chainId":"0x1","r":"0x1","s":"0x1"$extra}]}"""
        }
        assertTrue(valid(auth(""","v":"0x1b"""")).json.contains(""""yParity":"0x0""""))
        assertTrue(valid(auth(""","v":"0x1c"""")).json.contains(""""yParity":"0x1""""))
        assertTrue(valid(auth(""","v":"0x1c","yParity":"0x1"""")).json.contains(""""yParity":"0x1""""))
        assertTrue(refusal(auth(""","v":"0x1b","yParity":"0x1"""")).contains("disagree"))
    }

    @Test fun theLargestTypedNonceIsServed() {
        val tx = valid("""{"to":"0x2222222222222222222222222222222222222222","nonce":"0x7fffffffffffffff"}""")
        assertEquals(Long.MAX_VALUE, tx.nonce)
        assertTrue(tx.json.contains(""""nonce":"0x7fffffffffffffff""""), tx.json)
    }

    @Test fun aCreationNamingItsNonceHasExtendedFields() {
        assertTrue(valid("""{"data":"0x6000","nonce":"0x5"}""").hasExtendedFields)
        assertFalse(valid("""{"to":"0x2222222222222222222222222222222222222222","nonce":"0x5"}""").hasExtendedFields)
    }

    @Test fun equalDataAndInputAreOneCall() {
        assertEquals(
            """{"input":"0x01"}""",
            valid("""{"data":"0x01","input":"0x01"}""").json,
        )
    }

    companion object {
        /** The golden (see the class docs). Keys in the router's fixed order;
         *  hex lowercase; quantities minimal; `data` renamed `input`. */
        const val CANONICAL =
            """{"from":"0x1111111111111111111111111111111111111111",""" +
                """"to":"0x2222222222222222222222222222222222222222","input":"0x3e12cc2e",""" +
                """"value":"0x2386f26fc10000","maxFeePerGas":"0x3b9aca00","maxPriorityFeePerGas":"0x1",""" +
                """"nonce":"0x7","chainId":"0x1","type":"0x4",""" +
                """"accessList":[{"address":"0x3333333333333333333333333333333333333333",""" +
                """"storageKeys":["0x0000000000000000000000000000000000000000000000000000000000000001"]}],""" +
                """"authorizationList":[{"chainId":"0x1","address":"0x05ae73c5925d843864ae6f261f3175de2ebcd963",""" +
                """"nonce":"0x0","yParity":"0x1","r":"0x9a3b","s":"0xc5d"}]}"""
    }
}
