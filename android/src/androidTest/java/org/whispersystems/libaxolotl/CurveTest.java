package org.whispersystems.libaxolotl;

import junit.framework.TestCase;

import org.whispersystems.libaxolotl.ecc.Curve;
import org.whispersystems.libaxolotl.ecc.ECKeyPair;

public class CurveTest extends TestCase {

  public void testPureJava() {
    assertTrue(Curve.isNative());
  }

  public void testSignatureOverflow() throws InvalidKeyException {
    ECKeyPair keys    = Curve.generateKeyPair();
    byte[]    message = new byte[4096];

    try {
      byte[] signature = Curve.calculateSignature(keys.getPrivateKey(), message);
      throw new InvalidKeyException("Should have asserted!");
    } catch (AssertionError e) {
      // Success!
    }
  }

}
