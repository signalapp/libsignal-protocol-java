/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.groups.state;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.groups.ratchet.SenderChainKey;
import org.whispersystems.libsignal.groups.ratchet.SenderMessageKey;
import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.libsignal.util.SeedAndIteration;

import com.google.protobuf.InvalidProtocolBufferException;

import static org.whispersystems.libsignal.state.StorageProtos.SenderKeyStateStructure;

/**
 * Represents the state of an individual SenderKey ratchet.
 *
 * @author Moxie Marlinspike
 */
public class SenderKeyState {

  private static native long New(int id, int iteration, byte[] chainKey,
                                 long signaturePublicHandle,
                                 long signaturePrivateHandle);
  private static native void Destroy(long handle);

  private static native long Deserialize(byte[] serialized);
  private static native byte[] GetSerialized(long handle);
  private static native int GetKeyId(long handle);
  private static native long GetSigningKeyPublic(long handle);
  private static native long GetSigningKeyPrivate(long handle);

  private static native byte[] GetSenderChainKeySeed(long handle);
  private static native int GetSenderChainKeyIteration(long handle);

  private static native void SetSenderChainKey(long handle, int iteration, byte[] seed);
  private static native void AddSenderMessageKey(long handle, int iteration, byte[] seed);
  private static native boolean HasSenderMessageKey(long handle, int iteration);
  private static native long RemoveSenderMessageKey(long handle, int iteration);

  private long handle;

  public SenderKeyState(int id, int iteration, byte[] chainKey, ECPublicKey signatureKey) {
    this(id, iteration, chainKey, signatureKey, Optional.<ECPrivateKey>absent());
  }

  public SenderKeyState(int id, int iteration, byte[] chainKey, ECKeyPair signatureKey) {
    this(id, iteration, chainKey, signatureKey.getPublicKey(), Optional.of(signatureKey.getPrivateKey()));
  }

  private SenderKeyState(int id, int iteration, byte[] chainKey,
                        ECPublicKey signatureKeyPublic,
                        Optional<ECPrivateKey> signatureKeyPrivate)
  {
    long signatureKeyPrivateHandle = signatureKeyPrivate.isPresent() ? signatureKeyPrivate.get().nativeHandle() : 0;

    this.handle = New(id, iteration, chainKey, signatureKeyPublic.nativeHandle(),
                      signatureKeyPrivateHandle);
  }

  public SenderKeyState(SenderKeyStateStructure senderKeyStateStructure) {
    this.handle = Deserialize(senderKeyStateStructure.toByteArray());
  }

  public int getKeyId() {
    return GetKeyId(this.handle);
  }

  public SenderChainKey getSenderChainKey() {
    byte[] chainKey = GetSenderChainKeySeed(this.handle);
    int iteration = GetSenderChainKeyIteration(this.handle);
    return new SenderChainKey(iteration, chainKey);
  }

  public void setSenderChainKey(SenderChainKey chainKey) {
    SetSenderChainKey(this.handle, chainKey.getIteration(), chainKey.getSeed());
  }

  public ECPublicKey getSigningKeyPublic() throws InvalidKeyException {
    return new ECPublicKey(GetSigningKeyPublic(this.handle));
  }

  public ECPrivateKey getSigningKeyPrivate() {
    return new ECPrivateKey(GetSigningKeyPrivate(this.handle));
  }

  public boolean hasSenderMessageKey(int iteration) {
    return HasSenderMessageKey(this.handle, iteration);
  }

  public void addSenderMessageKey(SenderMessageKey senderMessageKey) {
    AddSenderMessageKey(this.handle,
                        senderMessageKey.getIteration(),
                        senderMessageKey.getSeed());
  }

  public SenderMessageKey removeSenderMessageKey(int iteration) {
    long result = RemoveSenderMessageKey(this.handle, iteration);
    if (result != 0) {
      SeedAndIteration seedAndIteration = new SeedAndIteration(result);
      return new SenderMessageKey(seedAndIteration.getIteration(), seedAndIteration.getSeed());
    } else {
      return null;
    }
  }

  public SenderKeyStateStructure getStructure() {
    try {
      return SenderKeyStateStructure.parseFrom(GetSerialized(this.handle));
    } catch (InvalidProtocolBufferException e) {
      throw new AssertionError(e);
    }
  }
}
