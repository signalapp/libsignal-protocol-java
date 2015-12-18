package org.whispersystems.libaxolotl.fingerprint;

public class FingerprintParsingException extends Exception {

  public FingerprintParsingException(Exception nested) {
    super(nested);
  }

}
