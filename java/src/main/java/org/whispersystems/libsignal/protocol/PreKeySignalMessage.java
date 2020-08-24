/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.guava.Optional;


public class PreKeySignalMessage implements CiphertextMessage {

  private static native long nativeDeserialize(byte[] serialized);
  private static native long nativeNew(int messageVersion,
                                 int registrationId,
                                 int preKeyId,
                                 int signedPreKeyId,
                                 long baseKeyHandle,
                                 long identityKeyHandle,
                                 long signalMessageHandle);
  private static native void nativeDestroy(long handle);
  private static native int nativeGetVersion(long handle);
  private static native int nativeGetRegistrationId(long handle);
  private static native int nativeGetPreKeyId(long handle);
  private static native int nativeGetSignedPreKeyId(long handle);
  private static native byte[] nativeGetBaseKey(long handle);
  private static native byte[] nativeGetIdentityKey(long handle);
  private static native byte[] nativeGetSignalMessage(long handle);
  private static native byte[] nativeGetSerialized(long handle);

  private long handle;

  @Override
  protected void finalize() {
     nativeDestroy(this.handle);
  }

  public PreKeySignalMessage(byte[] serialized)
      throws InvalidMessageException, InvalidVersionException
  {
    this.handle = nativeDeserialize(serialized);
  }

  public PreKeySignalMessage(long handle) {
    this.handle = handle;
  }

  public PreKeySignalMessage(int messageVersion, int registrationId, Optional<Integer> preKeyId,
                             int signedPreKeyId, ECPublicKey baseKey, IdentityKey identityKey,
                             SignalMessage message) {
    this.handle = nativeNew(messageVersion, registrationId, preKeyId.or(-1),
                      signedPreKeyId, baseKey.nativeHandle(),
                      identityKey.getPublicKey().nativeHandle(),
                      message.nativeHandle());
  }

  public int getMessageVersion() {
    return nativeGetVersion(this.handle);
  }

  public IdentityKey getIdentityKey() throws InvalidKeyException {
    return new IdentityKey(nativeGetIdentityKey(this.handle), 0);
  }

  public int getRegistrationId() {
    return nativeGetRegistrationId(this.handle);
  }

  public Optional<Integer> getPreKeyId() {
    int pre_key = nativeGetPreKeyId(this.handle);
    if(pre_key < 0) {
      return Optional.absent();
    } else {
      return Optional.of(pre_key);
    }
  }

  public int getSignedPreKeyId() {
    return nativeGetSignedPreKeyId(this.handle);
  }

  public ECPublicKey getBaseKey() throws InvalidKeyException {
    return new ECPublicKey(nativeGetBaseKey(this.handle));
  }

  public SignalMessage getWhisperMessage() throws InvalidMessageException, LegacyMessageException {
    return new SignalMessage(nativeGetSignalMessage(this.handle));
  }

  @Override
  public byte[] serialize() {
    return nativeGetSerialized(this.handle);
  }

  @Override
  public int getType() {
    return CiphertextMessage.PREKEY_TYPE;
  }

  public long nativeHandle() {
    return this.handle;
  }
}
