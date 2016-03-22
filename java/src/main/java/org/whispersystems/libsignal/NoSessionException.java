package org.whispersystems.libsignal;

public class NoSessionException extends Exception {
  public NoSessionException(String s) {
    super(s);
  }

  public NoSessionException(Exception nested) {
    super(nested);
  }
}
