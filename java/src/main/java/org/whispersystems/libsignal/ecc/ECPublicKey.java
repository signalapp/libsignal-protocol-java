/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.ecc;

import java.math.BigInteger;
import java.util.Arrays;

public class ECPublicKey implements Comparable<ECPublicKey> {

  public static final int KEY_SIZE = 33;

  static {
       System.loadLibrary("signal_jni");
  }

  private static native long nativeDeserialize(byte[] data, int offset);
  private static native byte[] nativeSerialize(long handle);
  private static native int nativeCompare(long handle1, long handle2);
  private static native boolean nativeVerify(long handle, byte[] message, byte[] signature);
  private static native void nativeDestroy(long handle);

  private final long handle;

  public ECPublicKey(byte[] serialized, int offset) {
    this.handle = nativeDeserialize(serialized, offset);
  }

  public ECPublicKey(byte[] serialized) {
    this.handle = nativeDeserialize(serialized, 0);
  }

  public ECPublicKey(long nativeHandle) {
    if (nativeHandle == 0) {
      throw new NullPointerException();
    }
    this.handle = nativeHandle;
  }

  @Override
  protected void finalize() {
     nativeDestroy(this.handle);
  }

  public boolean verifySignature(byte[] message, byte[] signature) {
    return nativeVerify(this.handle, message, signature);
  }

  public byte[] serialize() {
    return nativeSerialize(this.handle);
  }

  public int getType() {
    byte[] serialized = this.serialize();
    return serialized[0];
  }

  public long nativeHandle() {
    return this.handle;
  }

  @Override
  public boolean equals(Object other) {
    if (other == null)                      return false;
    if (!(other instanceof ECPublicKey)) return false;

    ECPublicKey that = (ECPublicKey)other;
    return Arrays.equals(this.serialize(), that.serialize());
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(this.serialize());
  }

  @Override
  public int compareTo(ECPublicKey another) {
    return nativeCompare(this.nativeHandle(), another.nativeHandle());
  }
}
