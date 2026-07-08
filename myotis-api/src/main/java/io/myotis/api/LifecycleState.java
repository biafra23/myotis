package io.myotis.api;

/**
 * Coarse lifecycle of one hosted network's stack.
 *
 * <ul>
 *   <li>{@code STOPPED} — never started, or fully shut down (terminal).</li>
 *   <li>{@code RUNNING} — networking live: discovery, RLPx, beacon sync, RPC.</li>
 *   <li>{@code PAUSED}  — pseudo-sleep: zero network sockets and zero periodic
 *       timers (the radio can sleep), but the stack instance and its warm
 *       verified state stay in memory and the JSON-RPC listener keeps
 *       listening. A verified read arriving while paused triggers
 *       {@link ChainHandle#resume()} and is held until the node can answer.</li>
 * </ul>
 */
public enum LifecycleState {
    STOPPED,
    RUNNING,
    PAUSED
}
