/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

import org.whispersystems.libsignal.IdentityKey;

public class NumericFingerprintGenerator implements FingerprintGenerator {

  private static native long nativeNew(int iterations, int version,
                                 byte[] localIdentifier, byte[] localKey,
                                 byte[] remoteIdentifier, byte[] remoteKey);

  private static native String nativeGetDisplayString(long handle);
  private static native byte[] nativeGetScannableEncoding(long handle);

  private static native void nativeDestroy(long handle);

  private static final int FINGERPRINT_VERSION = 0;

  private final int iterations;

  /**
   * Construct a fingerprint generator for 60 digit numerics.
   *
   * @param iterations The number of internal iterations to perform in the process of
   *                   generating a fingerprint. This needs to be constant, and synchronized
   *                   across all clients.
   *
   *                   The higher the iteration count, the higher the security level:
   *
   *                   - 1024 ~ 109.7 bits
   *                   - 1400 > 110 bits
   *                   - 5200 > 112 bits
   */
  public NumericFingerprintGenerator(int iterations) {
    this.iterations = iterations;
  }

  /**
   * Generate a scannable and displayable fingerprint.
   *
   * @param version The version of fingerprint you are generating.
   * @param localStableIdentifier The client's "stable" identifier.
   * @param localIdentityKey The client's identity key.
   * @param remoteStableIdentifier The remote party's "stable" identifier.
   * @param remoteIdentityKey The remote party's identity key.
   * @return A unique fingerprint for this conversation.
   */
  @Override
  public Fingerprint createFor(int version,
                               byte[] localStableIdentifier,
                               final IdentityKey localIdentityKey,
                               byte[] remoteStableIdentifier,
                               final IdentityKey remoteIdentityKey) {

    long handle = nativeNew(this.iterations, version,
                      localStableIdentifier,
                      localIdentityKey.serialize(),
                      remoteStableIdentifier,
                      remoteIdentityKey.serialize());

    DisplayableFingerprint displayableFingerprint = new DisplayableFingerprint(nativeGetDisplayString(handle));

    ScannableFingerprint scannableFingerprint = new ScannableFingerprint(nativeGetScannableEncoding(handle));

    nativeDestroy(handle);

    return new Fingerprint(displayableFingerprint, scannableFingerprint);
  }

}
