/**
 * Copyright (C) 2013 Open Whisper Systems
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
package org.whispersystems.libaxolotl.ecc;

import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;
import org.whispersystems.curve25519.NoSuchProviderException;
import org.whispersystems.libaxolotl.InvalidKeyException;

import static org.whispersystems.curve25519.Curve25519.BEST;

public class Curve {

  public  static final int DJB_TYPE   = 0x05;

  public static boolean isNative() {
    return Curve25519.getInstance(BEST).isNative();
  }

  public static ECKeyPair generateKeyPair() {
    Curve25519KeyPair keyPair = Curve25519.getInstance(BEST).generateKeyPair();

    return new ECKeyPair(new DjbECPublicKey(keyPair.getPublicKey()),
                         new DjbECPrivateKey(keyPair.getPrivateKey()));
  }

  public static ECPublicKey decodePoint(byte[] bytes, int offset)
      throws InvalidKeyException
  {
    int type = bytes[offset] & 0xFF;

    switch (type) {
      case Curve.DJB_TYPE:
        byte[] keyBytes = new byte[32];
        System.arraycopy(bytes, offset+1, keyBytes, 0, keyBytes.length);
        return new DjbECPublicKey(keyBytes);
      default:
        throw new InvalidKeyException("Bad key type: " + type);
    }
  }

  public static ECPrivateKey decodePrivatePoint(byte[] bytes) {
    return new DjbECPrivateKey(bytes);
  }

  public static byte[] calculateAgreement(ECPublicKey publicKey, ECPrivateKey privateKey)
      throws InvalidKeyException
  {
    if (publicKey.getType() != privateKey.getType()) {
      throw new InvalidKeyException("Public and private keys must be of the same type!");
    }

    if (publicKey.getType() == DJB_TYPE) {
      return Curve25519.getInstance(BEST)
                       .calculateAgreement(((DjbECPublicKey) publicKey).getPublicKey(),
                                           ((DjbECPrivateKey) privateKey).getPrivateKey());
    } else {
      throw new InvalidKeyException("Unknown type: " + publicKey.getType());
    }
  }

  public static boolean verifySignature(ECPublicKey signingKey, byte[] message, byte[] signature)
      throws InvalidKeyException
  {
    if (signingKey.getType() == DJB_TYPE) {
      return Curve25519.getInstance(BEST)
                       .verifySignature(((DjbECPublicKey) signingKey).getPublicKey(), message, signature);
    } else {
      throw new InvalidKeyException("Unknown type: " + signingKey.getType());
    }
  }

  public static byte[] calculateSignature(ECPrivateKey signingKey, byte[] message)
      throws InvalidKeyException
  {
    if (signingKey.getType() == DJB_TYPE) {
      return Curve25519.getInstance(BEST)
                       .calculateSignature(((DjbECPrivateKey) signingKey).getPrivateKey(), message);
    } else {
      throw new InvalidKeyException("Unknown type: " + signingKey.getType());
    }
  }
}
