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

package org.whispersystems.libaxolotl.groups.ratchet;

import org.whispersystems.libaxolotl.kdf.HKDFv3;
import org.whispersystems.libaxolotl.util.ByteUtil;

/**
 * The final symmetric material (IV and Cipher Key) used for encrypting
 * individual SenderKey messages.
 *
 * @author Moxie Marlinspike
 */
public class SenderMessageKey {

  private final int    iteration;
  private final byte[] iv;
  private final byte[] cipherKey;
  private final byte[] seed;

  public SenderMessageKey(int iteration, byte[] seed) {
    byte[] derivative = new HKDFv3().deriveSecrets(seed, "WhisperGroup".getBytes(), 48);
    byte[][] parts    = ByteUtil.split(derivative, 16, 32);

    this.iteration = iteration;
    this.seed      = seed;
    this.iv        = parts[0];
    this.cipherKey = parts[1];
  }

  public int getIteration() {
    return iteration;
  }

  public byte[] getIv() {
    return iv;
  }

  public byte[] getCipherKey() {
    return cipherKey;
  }

  public byte[] getSeed() {
    return seed;
  }
}
