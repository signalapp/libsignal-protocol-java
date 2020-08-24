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

  private static native long nativeGenerate();
  private static native long nativeDeserialize(byte[] data);
  private static native byte[] nativeSerialize(long handle);
  private static native byte[] nativeSign(long handle, byte[] message);
  private static native byte[] nativeAgree(long handle, long pubkey_handle);
  private static native long nativeGetPublicKey(long handle);
  private static native void nativeDestroy(long handle);

  private long handle;

  ECPrivateKey() {
    this.handle = nativeGenerate();
  }

  ECPrivateKey(byte[] privateKey) {
    this.handle = nativeDeserialize(privateKey);
  }

  public ECPrivateKey(long nativeHandle) {
    if(nativeHandle == 0) {
      throw new NullPointerException();
    }
    this.handle = nativeHandle;
  }

  @Override
  protected void finalize() {
     nativeDestroy(this.handle);
  }

  public byte[] serialize() {
    return nativeSerialize(this.handle);
  }

  public byte[] calculateSignature(byte[] message) {
     return nativeSign(this.handle, message);
  }

  public byte[] calculateAgreement(ECPublicKey other) {
    return nativeAgree(this.handle, other.nativeHandle());
  }

  public long nativeHandle() {
    return this.handle;
  }

  public ECPublicKey publicKey() {
    return new ECPublicKey(nativeGetPublicKey(this.handle));
  }
}
