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

public class PreKeyRecord {

  private static native long nativeNew(int id,
                                 long pubKeyHandle,
                                 long privKeyHandle);
  private static native long nativeDeserialize(byte[] serialized);
  private static native void nativeDestroy(long handle);

  private static native int nativeGetId(long handle);
  private static native long nativeGetPublicKey(long handle);
  private static native long nativeGetPrivateKey(long handle);
  private static native byte[] nativeGetSerialized(long handle);

  private long handle;

  @Override
  protected void finalize() {
    nativeDestroy(this.handle);
  }

  public PreKeyRecord(int id, ECKeyPair keyPair) {
    this.handle = nativeNew(id, keyPair.getPublicKey().nativeHandle(), keyPair.getPrivateKey().nativeHandle());
  }

  public PreKeyRecord(byte[] serialized) throws IOException {
    this.handle = nativeDeserialize(serialized);
  }

  public int getId() {
    return nativeGetId(this.handle);
  }

  public ECKeyPair getKeyPair() {
    ECPublicKey publicKey = new ECPublicKey(nativeGetPublicKey(this.handle));
    ECPrivateKey privateKey = new ECPrivateKey(nativeGetPrivateKey(this.handle));
    return new ECKeyPair(publicKey, privateKey);
  }

  public byte[] serialize() {
    return nativeGetSerialized(this.handle);
  }

  public long nativeHandle() {
    return this.handle;
  }
}
