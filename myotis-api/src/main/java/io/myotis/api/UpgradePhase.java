package io.myotis.api;

/**
 * How far along an {@link UpgradeAdvisory}'s network upgrade is: {@code SCHEDULED} while
 * its activation lies ahead (update before then), {@code ACTIVE} once it has passed (this
 * build can no longer follow the network).
 */
public enum UpgradePhase { SCHEDULED, ACTIVE }
