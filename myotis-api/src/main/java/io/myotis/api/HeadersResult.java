package io.myotis.api;

import java.util.List;

/**
 * Result of a header-range fetch. A fetch failure (no peer, timeout) sets
 * {@link #error} and leaves {@link #headers} empty.
 *
 * @param headers the fetched headers, in ascending block order
 * @param error   null on success; otherwise a human-readable failure message
 */
public record HeadersResult(List<HeaderInfo> headers, String error) {
}
