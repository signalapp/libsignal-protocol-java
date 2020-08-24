/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;

import java.io.IOException;

public class SignedPreKeyRecord {

  private static native long nativeNew(int id, long timestamp,
                                 long pubKeyHandle,
                                 long privKeyHandle,
                                 byte[] signature);
  private static native long nativeDeserialize(byte[] serialized);
  private static native void nativeDestroy(long handle);

  private static native int nativeGetId(long handle);
  private static native long nativeGetTimestamp(long handle);
  private static native long nativeGetPublicKey(long handle);
  private static native long nativeGetPrivateKey(long handle);
  private static native byte[] nativeGetSignature(long handle);
  private static native byte[] nativeGetSerialized(long handle);

  private long handle;

  @Override
  protected void finalize() {
    nativeDestroy(this.handle);
  }

  public SignedPreKeyRecord(int id, long timestamp, ECKeyPair keyPair, byte[] signature) {
    this.handle = nativeNew(id, timestamp,
                      keyPair.getPublicKey().nativeHandle(),
                      keyPair.getPrivateKey().nativeHandle(),
                      signature);
  }

  public SignedPreKeyRecord(byte[] serialized) throws IOException {
    this.handle = nativeDeserialize(serialized);
  }

  public int getId() {
    return nativeGetId(this.handle);
  }

  public long getTimestamp() {
    return nativeGetTimestamp(this.handle);
  }

  public ECKeyPair getKeyPair() {
    ECPublicKey publicKey = new ECPublicKey(nativeGetPublicKey(this.handle));
    ECPrivateKey privateKey = new ECPrivateKey(nativeGetPrivateKey(this.handle));
    return new ECKeyPair(publicKey, privateKey);
  }

  public byte[] getSignature() {
    return nativeGetSignature(this.handle);
  }

  public byte[] serialize() {
    return nativeGetSerialized(this.handle);
  }

  public long nativeHandle() {
    return this.handle;
  }

}
