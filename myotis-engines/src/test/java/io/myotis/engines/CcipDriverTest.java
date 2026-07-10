package io.myotis.engines;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonObject;
import io.myotis.api.EngineException;
import io.myotis.api.ports.HttpGateway;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The host half of CCIP-Read, driven with fakes — no JNI, no HTTP. */
class CcipDriverTest {

    private static final String SENDER = "0x" + "5e".repeat(20);

    /**
     * The exact envelope {@code eljson::ens_record_json} emits for a parsed
     * OffchainLookup (its {@code ens_record_json_shapes} test pins the same
     * literals — the two are the halves of the cross-language pin).
     */
    private static String offchainJson(String... urls) {
        StringBuilder u = new StringBuilder();
        for (String url : urls) {
            if (u.length() > 0) {
                u.append(',');
            }
            u.append('"').append(url).append('"');
        }
        return "{\"status\":\"offchain\",\"blockNumber\":21000010,\"verified\":true,"
                + "\"wrapped\":true,\"senderHex\":\"" + SENDER + "\",\"urls\":[" + u + "],"
                + "\"callDataHex\":\"0xca11\",\"callbackFunctionHex\":\"0xcbcbcbcb\","
                + "\"extraDataHex\":\"0xeeeeee\"}";
    }

    private static JsonObject addrParams() {
        return Json.object().add("method", "addr").add("name", "offchain.eth").add("root", "auto");
    }

    /** A scripted gateway recording each request. */
    private static final class FakeGateway implements HttpGateway {
        record Req(Method method, String url, String body) {}
        final List<Req> requests = new ArrayList<>();
        private final List<Object> outcomes; // String response or RuntimeException

        FakeGateway(Object... outcomes) {
            this.outcomes = List.of(outcomes);
        }

        @Override
        public String request(Method method, String url, String bodyOrNull) {
            requests.add(new Req(method, url, bodyOrNull));
            Object o = outcomes.get(Math.min(requests.size() - 1, outcomes.size() - 1));
            if (o instanceof RuntimeException e) {
                throw e;
            }
            return (String) o;
        }
    }

    @Test
    void getWhenTemplateHasDataPlaceholderAndSubstitutes() {
        var gw = new FakeGateway("{\"data\":\"0xaa\"}");
        List<String> nativeCalls = new ArrayList<>();
        String result = CcipDriver.drive(addrParams(),
                offchainJson("https://gw.example/{sender}/{data}.json"), gw, p -> {
                    nativeCalls.add(p);
                    return "{\"status\":\"ok\",\"blockNumber\":21000010,\"verified\":true,"
                            + "\"addressHex\":\"0x" + "d8".repeat(20) + "\"}";
                });
        assertEquals(1, gw.requests.size());
        var req = gw.requests.get(0);
        assertEquals(HttpGateway.Method.GET, req.method());
        assertEquals("https://gw.example/" + SENDER + "/0xca11.json", req.url());
        assertEquals(null, req.body());
        // The callback params carry the original query + the tuple + the response.
        JsonObject cb = Json.parse(nativeCalls.get(0)).asObject();
        assertEquals("ccipCallback", cb.getString("method", null));
        assertEquals("addr", cb.getString("queryMethod", null));
        assertEquals("offchain.eth", cb.getString("name", null));
        assertEquals(SENDER, cb.getString("senderHex", null));
        assertEquals("0xaa", cb.getString("responseHex", null));
        assertEquals("0xeeeeee", cb.getString("extraDataHex", null));
        assertTrue(cb.getBoolean("wrapped", false));
        assertTrue(cb.getBoolean("finalized", false)); // verified:true → same root
        // And the driver returns the callback's final JSON.
        assertTrue(result.contains("\"status\":\"ok\""));
    }

    @Test
    void postWhenNoDataPlaceholder() {
        var gw = new FakeGateway("{\"data\":\"0xaa\"}");
        CcipDriver.drive(addrParams(), offchainJson("https://gw.example/query"), gw,
                p -> "{\"status\":\"noRecord\",\"blockNumber\":1,\"verified\":false}");
        var req = gw.requests.get(0);
        assertEquals(HttpGateway.Method.POST, req.method());
        assertEquals("{\"sender\":\"" + SENDER + "\",\"data\":\"0xca11\"}", req.body());
    }

    @Test
    void urlsTriedSeriallyFirstParseableWins() {
        var gw = new FakeGateway(
                new RuntimeException("HTTP 503"),          // url1 transport failure
                "not json at all",                          // url2 unparseable
                "{\"data\":\"0x1234\"}");                   // url3 wins
        List<String> nativeCalls = new ArrayList<>();
        CcipDriver.drive(addrParams(), offchainJson("u1", "u2", "u3"), gw, p -> {
            nativeCalls.add(p);
            return "{\"status\":\"noRecord\",\"blockNumber\":1,\"verified\":false}";
        });
        assertEquals(3, gw.requests.size());
        assertEquals(1, nativeCalls.size());
        assertTrue(nativeCalls.get(0).contains("\"responseHex\":\"0x1234\""));
    }

    @Test
    void httpErrorSelectorCountsAsGatewayFailure() {
        // 0xca7a4e75 anywhere (even hex offset) in the data → that URL failed.
        var gw = new FakeGateway("{\"data\":\"0x00ca7a4e7500\"}");
        EngineException e = assertThrows(EngineException.class, () -> CcipDriver.drive(
                addrParams(), offchainJson("only"), gw, p -> "unused"));
        assertTrue(e.getMessage().contains("HttpError"), e.getMessage());
    }

    @Test
    void allGatewaysFailingCarriesPerUrlReasons() {
        var gw = new FakeGateway(new RuntimeException("boom"), "no data field here");
        EngineException e = assertThrows(EngineException.class, () -> CcipDriver.drive(
                addrParams(), offchainJson("u1", "u2"), gw, p -> "unused"));
        assertTrue(e.getMessage().contains("u1"), e.getMessage());
        assertTrue(e.getMessage().contains("unparseable response from u2"), e.getMessage());
    }

    @Test
    void secondOffchainHitsTheRecursionCap() {
        var gw = new FakeGateway("{\"data\":\"0xaa\"}");
        // The callback itself reverts OffchainLookup again → cap 1 exceeded.
        EngineException e = assertThrows(EngineException.class, () -> CcipDriver.drive(
                addrParams(), offchainJson("u"), gw, p -> offchainJson("u")));
        assertTrue(e.getMessage().contains("recursion depth"), e.getMessage());
        assertEquals(1, gw.requests.size()); // no second gateway round
    }

    @Test
    void nonActionableJsonPassesThrough() {
        var gw = new FakeGateway("unused");
        // ok / noRecord / error / offchain-without-tuple all pass through untouched.
        for (String json : new String[] {
                "{\"status\":\"ok\",\"blockNumber\":1,\"verified\":false,\"addressHex\":\"0xab\"}",
                "{\"status\":\"noRecord\",\"blockNumber\":1,\"verified\":false}",
                "{\"error\":\"no snap peer\"}",
                "{\"status\":\"offchain\",\"blockNumber\":1,\"verified\":false,\"wrapped\":false}",
                "not json"}) {
            assertEquals(json, CcipDriver.drive(addrParams(), json, gw, p -> "unused"));
        }
        assertEquals(0, gw.requests.size());
    }

    @Test
    void oddLengthDataHexFailsOverToNextUrl() {
        // Odd-length hex can never decode natively — the driver must record it
        // and try the NEXT url, not ship it to the native after failover ends.
        var gw = new FakeGateway("{\"data\":\"0xabc\"}", "{\"data\":\"0xabcd\"}");
        List<String> nativeCalls = new ArrayList<>();
        CcipDriver.drive(addrParams(), offchainJson("u1", "u2"), gw, p -> {
            nativeCalls.add(p);
            return "{\"status\":\"noRecord\",\"blockNumber\":1,\"verified\":false}";
        });
        assertEquals(2, gw.requests.size());
        assertTrue(nativeCalls.get(0).contains("\"responseHex\":\"0xabcd\""));
    }

    @Test
    void senderOnlyTemplateIsPostWithSubstitution() {
        var gw = new FakeGateway("{\"data\":\"0xaa\"}");
        CcipDriver.drive(addrParams(), offchainJson("https://gw.example/{sender}"), gw,
                p -> "{\"status\":\"noRecord\",\"blockNumber\":1,\"verified\":false}");
        var req = gw.requests.get(0);
        // No {data} in the template → POST, with {sender} still substituted.
        assertEquals(HttpGateway.Method.POST, req.method());
        assertEquals("https://gw.example/" + SENDER, req.url());
    }

    @Test
    void offchainWithoutGatewayIsAnError() {
        EngineException e = assertThrows(EngineException.class, () -> CcipDriver.drive(
                addrParams(), offchainJson("u"), null, p -> "unused"));
        assertTrue(e.getMessage().contains("no CCIP-Read HTTP gateway"), e.getMessage());
    }
}
