package org.whispersystems.libsignal.fingerprint;

public class FingerprintParsingException extends Exception {

  public FingerprintParsingException(Exception nested) {
    super(nested);
  }

}
