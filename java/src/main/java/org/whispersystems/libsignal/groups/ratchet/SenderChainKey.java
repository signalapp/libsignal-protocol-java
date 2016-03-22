/**
 * Copyright (C) 2014-2015 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.whispersystems.libsignal.groups.ratchet;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Each SenderKey is a "chain" of keys, each derived from the previous.
 *
 * At any given point in time, the state of a SenderKey can be represented
 * as the current chain key value, along with its iteration count.  From there,
 * subsequent iterations can be derived, as well as individual message keys from
 * each chain key.
 *
 * @author Moxie Marlinspike
 */
public class SenderChainKey {

  private static final byte[] MESSAGE_KEY_SEED = {0x01};
  private static final byte[] CHAIN_KEY_SEED   = {0x02};

  private final int    iteration;
  private final byte[] chainKey;

  public SenderChainKey(int iteration, byte[] chainKey) {
    this.iteration = iteration;
    this.chainKey  = chainKey;
  }

  public int getIteration() {
    return iteration;
  }

  public SenderMessageKey getSenderMessageKey() {
    return new SenderMessageKey(iteration, getDerivative(MESSAGE_KEY_SEED, chainKey));
  }

  public SenderChainKey getNext() {
    return new SenderChainKey(iteration + 1, getDerivative(CHAIN_KEY_SEED, chainKey));
  }

  public byte[] getSeed() {
    return chainKey;
  }

  private byte[] getDerivative(byte[] seed, byte[] key) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));

      return mac.doFinal(seed);
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

}
