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

import static org.whispersystems.libsignal.state.StorageProtos.SignedPreKeyRecordStructure;

public class SignedPreKeyRecord {

  private static native long New(int id, long timestamp,
                                 long pubKeyHandle,
                                 long privKeyHandle,
                                 byte[] signature);
  private static native long Deserialize(byte[] serialized);
  private static native void Destroy(long handle);

  private static native int GetId(long handle);
  private static native long GetTimestamp(long handle);
  private static native long GetPublicKey(long handle);
  private static native long GetPrivateKey(long handle);
  private static native byte[] GetSignature(long handle);
  private static native byte[] GetSerialized(long handle);

  private long handle;

  @Override
  protected void finalize() {
    Destroy(this.handle);
  }

  public SignedPreKeyRecord(int id, long timestamp, ECKeyPair keyPair, byte[] signature) {
    this.handle = New(id, timestamp,
                      keyPair.getPublicKey().nativeHandle(),
                      keyPair.getPrivateKey().nativeHandle(),
                      signature);
  }

  public SignedPreKeyRecord(byte[] serialized) throws IOException {
    this.handle = Deserialize(serialized);
  }

  public int getId() {
    return GetId(this.handle);
  }

  public long getTimestamp() {
    return GetTimestamp(this.handle);
  }

  public ECKeyPair getKeyPair() {
    ECPublicKey publicKey = new ECPublicKey(GetPublicKey(this.handle));
    ECPrivateKey privateKey = new ECPrivateKey(GetPrivateKey(this.handle));
    return new ECKeyPair(publicKey, privateKey);
  }

  public byte[] getSignature() {
    return GetSignature(this.handle);
  }

  public byte[] serialize() {
    return GetSerialized(this.handle);
  }
}
