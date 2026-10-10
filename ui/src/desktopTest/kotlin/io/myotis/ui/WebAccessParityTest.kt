package io.myotis.ui

import io.myotis.jsonrpc.WebOrigins
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The UI's origin reduction must be the engine's, or a site typed in Settings and
 * the origin the gate records never compare equal (Allow then admits nothing). The
 * two copies live in modules that cannot share code (`:ui` is dependency-free
 * multiplatform; the engine's is in `:jsonrpc-server`), so this pins them to each
 * other over a corpus wide enough that a change to one side's rules fails here.
 */
class WebAccessParityTest {

    private val corpus = listOf(
        "app.example", "  App.Example/ ", "HTTPS://App.Example:443/", "http://app.example:80",
        "http://localhost:3000", "https://app.example:8443", "http://[::1]:3000", "http://[::1]",
        "chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn",
        "moz-extension://3C8D0F2A-1b2c-4d5e-8f90-123456789abc/",
        "", "   ", "null", "NULL", "https://app.example/path", "https://app.example?x=1",
        "https://app.example#f", "https://user@app.example", "https://app.example:0",
        "https://app.example:99999", "https://app.example:abc", "https://app.example:",
        "ht tp://app.example", "*.example.org", "https://*.example.org", "://app.example",
        "1http://app.example", "http://[::1", "http://[::1]x", "http://[zz::1]", "https://",
        "ws://app.example:80", "wss://app.example:443", "ftp://files.example:21",
        "https://xn--mnchen-3ya.example", "https://münchen.example", "https://аpp.example",
        "https://app.example:８０", "https://app_1.example", "https://app-1.example.",
        "HTTP://LOCALHOST", "http://127.0.0.1:8545/", "https://app.example:00443",
        "https://app.example:65535", "https://app.example:65536", "http:/app.example",
        "http:///app.example", "https://app.example\\", "https://a.example,b.example",
    )

    @Test fun uiAndEngineReduceEveryInputTheSameWay() {
        for (input in corpus) {
            assertEquals("'$input'", WebOrigins.normalize(input), WebAccessUi.normalize(input))
        }
        // And the same for every string made of the characters an origin can contain, up
        // to a short length: a brute-force sweep of the edge cases no list would think of.
        val alphabet = "ab1:/.[]-_@?#* ü"
        fun sweep(prefix: String, depth: Int) {
            if (depth == 0) return
            for (c in alphabet) {
                val s = prefix + c
                assertEquals("'$s'", WebOrigins.normalize(s), WebAccessUi.normalize(s))
                sweep(s, depth - 1)
            }
        }
        sweep("", 4)
        sweep("https://", 3)
        sweep("http://[", 3)
    }
}
