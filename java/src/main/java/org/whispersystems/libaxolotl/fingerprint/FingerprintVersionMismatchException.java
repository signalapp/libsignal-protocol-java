package org.whispersystems.libaxolotl.fingerprint;

public class FingerprintVersionMismatchException extends Exception {

  public FingerprintVersionMismatchException() {
    super();
  }

  public FingerprintVersionMismatchException(Exception e) {
    super(e);
  }
}
