package io.myotis.api.ports;

/**
 * A cached EL peer's learned snap-serving verdict — drives dial priority
 * (CONFIRMED first).
 */
public enum SnapQuality { CONFIRMED, UNKNOWN, DENIED }
