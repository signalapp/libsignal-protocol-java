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

import static org.whispersystems.libsignal.state.StorageProtos.PreKeyRecordStructure;

public class PreKeyRecord {

  private static native long New(int id,
                                 long pubKeyHandle,
                                 long privKeyHandle);
  private static native long Deserialize(byte[] serialized);
  private static native void Destroy(long handle);

  private static native int GetId(long handle);
  private static native long GetPublicKey(long handle);
  private static native long GetPrivateKey(long handle);
  private static native byte[] GetSerialized(long handle);

  private long handle;

  @Override
  protected void finalize() {
    Destroy(this.handle);
  }

  public PreKeyRecord(int id, ECKeyPair keyPair) {
    this.handle = New(id, keyPair.getPublicKey().nativeHandle(), keyPair.getPrivateKey().nativeHandle());
  }

  public PreKeyRecord(byte[] serialized) throws IOException {
    this.handle = Deserialize(serialized);
  }

  public int getId() {
    return GetId(this.handle);
  }

  public ECKeyPair getKeyPair() {
    ECPublicKey publicKey = new ECPublicKey(GetPublicKey(this.handle));
    ECPrivateKey privateKey = new ECPrivateKey(GetPrivateKey(this.handle));
    return new ECKeyPair(publicKey, privateKey);
  }

  public byte[] serialize() {
    return GetSerialized(this.handle);
  }
}
