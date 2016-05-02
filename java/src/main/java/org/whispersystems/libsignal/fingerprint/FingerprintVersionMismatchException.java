/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

public class FingerprintVersionMismatchException extends Exception {

  public FingerprintVersionMismatchException() {
    super();
  }

  public FingerprintVersionMismatchException(Exception e) {
    super(e);
  }
}
