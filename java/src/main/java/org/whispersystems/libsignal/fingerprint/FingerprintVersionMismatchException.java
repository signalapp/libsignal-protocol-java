package org.whispersystems.libsignal.fingerprint;

public class FingerprintVersionMismatchException extends Exception {

  public FingerprintVersionMismatchException() {
    super();
  }

  public FingerprintVersionMismatchException(Exception e) {
    super(e);
  }
}
