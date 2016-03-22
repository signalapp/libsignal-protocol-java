package org.whispersystems.libsignal;

public interface DecryptionCallback {
  public void handlePlaintext(byte[] plaintext);
}