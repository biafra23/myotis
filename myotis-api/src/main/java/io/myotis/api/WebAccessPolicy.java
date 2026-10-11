package io.myotis.api;

import java.util.List;

/**
 * The operator's web-page access policy for the JSON-RPC listener (#502).
 *
 * @param mode    which pages may use the node
 * @param origins the exact origins {@link WebAccessMode#ALLOWLIST} admits, as
 *                {@code scheme://host[:port]}; a bare domain means
 *                {@code https://<domain>}. The engine normalizes each entry
 *                (lowercase, default port dropped) and drops what is not a plain
 *                origin — no wildcards, never the opaque origin {@code null}.
 *                Ignored by the other modes, but kept so switching back restores
 *                the list.
 */
public record WebAccessPolicy(WebAccessMode mode, List<String> origins) {

    /** Specific sites, none yet: every web page is refused until the operator allows it. */
    public static final WebAccessPolicy DEFAULT = new WebAccessPolicy(WebAccessMode.ALLOWLIST, List.of());

    public WebAccessPolicy {
        if (mode == null) throw new IllegalArgumentException("mode is required");
        origins = origins == null ? List.of() : List.copyOf(origins);
    }
}
