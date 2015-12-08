package org.whispersystems.libaxolotl.fingerprint;

import junit.framework.TestCase;

import org.whispersystems.libaxolotl.IdentityKey;
import org.whispersystems.libaxolotl.ecc.Curve;
import org.whispersystems.libaxolotl.ecc.ECKeyPair;

public class NumericFingerprintGeneratorTest extends TestCase {

  public void testMatchingFingerprints() throws FingerprintVersionMismatchException, FingerprintIdentifierMismatchException {
    ECKeyPair aliceKeyPair = Curve.generateKeyPair();
    ECKeyPair bobKeyPair   = Curve.generateKeyPair();

    IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.getPublicKey());
    IdentityKey bobIdentityKey   = new IdentityKey(bobKeyPair.getPublicKey());

    NumericFingerprintGenerator generator        = new NumericFingerprintGenerator(1024);
    Fingerprint                 aliceFingerprint = generator.createFor("+14152222222", aliceIdentityKey,
                                                                       "+14153333333", bobIdentityKey);

    Fingerprint bobFingerprint = generator.createFor("+14153333333", bobIdentityKey,
                                                     "+14152222222", aliceIdentityKey);

    assertEquals(aliceFingerprint.getDisplayableFingerprint().getDisplayText(),
                 bobFingerprint.getDisplayableFingerprint().getDisplayText());

    assertTrue(aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
    assertTrue(bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));

    assertEquals(aliceFingerprint.getDisplayableFingerprint().getDisplayText().length(), 60);
  }

  public void testMismatchingFingerprints() throws FingerprintVersionMismatchException, FingerprintIdentifierMismatchException {
    ECKeyPair aliceKeyPair = Curve.generateKeyPair();
    ECKeyPair bobKeyPair   = Curve.generateKeyPair();
    ECKeyPair mitmKeyPair  = Curve.generateKeyPair();

    IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.getPublicKey());
    IdentityKey bobIdentityKey   = new IdentityKey(bobKeyPair.getPublicKey());
    IdentityKey mitmIdentityKey  = new IdentityKey(mitmKeyPair.getPublicKey());

    NumericFingerprintGenerator generator        = new NumericFingerprintGenerator(1024);
    Fingerprint                 aliceFingerprint = generator.createFor("+14152222222", aliceIdentityKey,
                                                                       "+14153333333", mitmIdentityKey);

    Fingerprint bobFingerprint = generator.createFor("+14153333333", bobIdentityKey,
                                                     "+14152222222", aliceIdentityKey);

    assertNotSame(aliceFingerprint.getDisplayableFingerprint().getDisplayText(),
                  bobFingerprint.getDisplayableFingerprint().getDisplayText());

    assertFalse(aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
    assertFalse(bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));
  }

  public void testMismatchingIdentifiers() throws FingerprintVersionMismatchException {
    ECKeyPair aliceKeyPair = Curve.generateKeyPair();
    ECKeyPair bobKeyPair   = Curve.generateKeyPair();

    IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.getPublicKey());
    IdentityKey bobIdentityKey   = new IdentityKey(bobKeyPair.getPublicKey());

    NumericFingerprintGenerator generator        = new NumericFingerprintGenerator(1024);
    Fingerprint                 aliceFingerprint = generator.createFor("+141512222222", aliceIdentityKey,
                                                                       "+14153333333", bobIdentityKey);

    Fingerprint bobFingerprint = generator.createFor("+14153333333", bobIdentityKey,
                                                     "+14152222222", aliceIdentityKey);

    assertNotSame(aliceFingerprint.getDisplayableFingerprint().getDisplayText(),
                  bobFingerprint.getDisplayableFingerprint().getDisplayText());

    try {;
      aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized());
      throw new AssertionError("Should mismatch!");
    } catch (FingerprintIdentifierMismatchException e) {
      // good
    }

    try {
      bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized());
      throw new AssertionError("Should mismatch!");
    } catch (FingerprintIdentifierMismatchException e) {
      // good
    }
  }

}
