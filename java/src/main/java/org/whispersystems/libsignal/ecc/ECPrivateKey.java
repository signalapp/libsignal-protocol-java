/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.ecc;

public class ECPrivateKey {
  static {
       System.loadLibrary("signal_jni");
  }

  private static native long Deserialize(byte[] data);
  private static native byte[] Serialize(long handle);
  private static native byte[] Sign(long handle, byte[] message);
  private static native byte[] Agree(long handle, long pubkey_handle);
  private static native void Destroy(long handle);

  private long handle;

  ECPrivateKey(byte[] privateKey) {
    this.handle = Deserialize(privateKey);
  }

  public ECPrivateKey(long nativeHandle) {
    if(nativeHandle == 0) {
      throw new NullPointerException();
    }
    this.handle = nativeHandle;
  }

  @Override
  protected void finalize() {
     Destroy(this.handle);
  }

  public byte[] serialize() {
    return Serialize(this.handle);
  }

  public byte[] calculateSignature(byte[] message) {
     return Sign(this.handle, message);
  }

  public byte[] calculateAgreement(ECPublicKey other) {
    return Agree(this.handle, other.nativeHandle());
  }

  public long nativeHandle() {
    return handle;
  }
}
