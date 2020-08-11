/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

public class ScannableFingerprint {

  private static native boolean Compare(byte[] ourFingerprint, byte[] scannedFingerprint);

  private final byte[] encodedFingerprint;

  ScannableFingerprint(byte[] encodedFingerprint) {
    this.encodedFingerprint = encodedFingerprint;
  }

  /**
   * @return A byte string to be displayed in a QR code.
   */
  public byte[] getSerialized() {
    return this.encodedFingerprint;
  }

  /**
   * Compare a scanned QR code with what we expect.
   *
   * @param scannedFingerprintData The scanned data
   * @return True if matching, otherwise false.
   * @throws FingerprintVersionMismatchException if the scanned fingerprint is the wrong version.
   */
  public boolean compareTo(byte[] scannedFingerprintData)
      throws FingerprintVersionMismatchException,
             FingerprintParsingException
  {
    return Compare(this.encodedFingerprint, scannedFingerprintData);
  }
}
