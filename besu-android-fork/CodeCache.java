/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.evm.internal;

import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.evm.Code;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The Code cache.
 *
 * <p>ANDROID PATCH: backed by a {@link LinkedHashMap} LRU instead of Caffeine.
 * Caffeine's StripedBuffer.&lt;clinit&gt; reflects into the JDK-internal field
 * {@code java.lang.Thread.threadLocalRandomProbe} (via Unsafe), which does not
 * exist on Android's ART runtime, so building any Caffeine cache throws
 * NoSuchFieldException at EVM construction time. This is not fixable by a
 * Caffeine version pin. The cache is a pure performance optimisation, so a
 * simple entry-bounded LRU preserves behaviour. (CodeScale, the Caffeine
 * weigher, is now unused and may be deleted.)
 */
public class CodeCache {

  /**
   * Entry cap for the LRU. Besu's default jump-dest cache weight is ~32 MB;
   * bytecode entries are a few KB each, so a few thousand entries is a
   * comparable working set. Bounded by count to avoid Caffeine's weigher.
   */
  private static final int MAX_ENTRIES = 4_096;

  private final Map<Hash, Code> cache;
  private final long weightLimit;

  /**
   * Instantiates a new Code cache.
   *
   * @param config the config
   */
  public CodeCache(final EvmConfiguration config) {
    this(config.getJumpDestCacheWeightBytes());
  }

  private CodeCache(final long maxWeightBytes) {
    this.weightLimit = maxWeightBytes;
    this.cache =
        Collections.synchronizedMap(
            new LinkedHashMap<Hash, Code>(64, 0.75f, true) {
              @Override
              protected boolean removeEldestEntry(final Map.Entry<Hash, Code> eldest) {
                return size() > MAX_ENTRIES;
              }
            });
  }

  /**
   * Invalidate cache for given key.
   *
   * @param key the key
   */
  public void invalidate(final Hash key) {
    cache.remove(key);
  }

  /** Clean up. */
  public void cleanUp() {
    // No background maintenance to flush (unlike Caffeine); no-op.
  }

  /**
   * Gets if present.
   *
   * @param codeHash the code hash
   * @return the if present
   */
  public Code getIfPresent(final Hash codeHash) {
    return cache.get(codeHash);
  }

  /**
   * Put.
   *
   * @param key the key
   * @param value the value
   */
  public void put(final Hash key, final Code value) {
    cache.put(key, value);
  }

  /**
   * Size of cache.
   *
   * @return the long
   */
  public long size() {
    return cache.size();
  }

  /**
   * Gets weight limit.
   *
   * @return the weight limit
   */
  public long getWeightLimit() {
    return weightLimit;
  }
}
