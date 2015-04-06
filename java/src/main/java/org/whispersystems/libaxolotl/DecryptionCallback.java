package org.whispersystems.libaxolotl;

public interface DecryptionCallback {
  public void handlePlaintext(byte[] plaintext);
}