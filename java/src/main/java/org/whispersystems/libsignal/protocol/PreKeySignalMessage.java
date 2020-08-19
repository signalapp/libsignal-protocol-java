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

  private static native long Deserialize(byte[] serialized);
  private static native long New(int messageVersion,
                                 int registrationId,
                                 int preKeyId,
                                 int signedPreKeyId,
                                 long baseKeyHandle,
                                 long identityKeyHandle,
                                 long signalMessageHandle);
  private static native void Destroy(long handle);
  private static native int GetVersion(long handle);
  private static native int GetRegistrationId(long handle);
  private static native int GetPreKeyId(long handle);
  private static native int GetSignedPreKeyId(long handle);
  private static native byte[] GetBaseKey(long handle);
  private static native byte[] GetIdentityKey(long handle);
  private static native byte[] GetSignalMessage(long handle);
  private static native byte[] GetSerialized(long handle);

  private long handle;

  @Override
  protected void finalize() {
     Destroy(this.handle);
  }

  public PreKeySignalMessage(byte[] serialized)
      throws InvalidMessageException, InvalidVersionException
  {
    this.handle = Deserialize(serialized);
  }

  public PreKeySignalMessage(long handle) {
    this.handle = handle;
  }

  public PreKeySignalMessage(int messageVersion, int registrationId, Optional<Integer> preKeyId,
                             int signedPreKeyId, ECPublicKey baseKey, IdentityKey identityKey,
                             SignalMessage message) {
    this.handle = New(messageVersion, registrationId, preKeyId.or(-1),
                      signedPreKeyId, baseKey.nativeHandle(),
                      identityKey.getPublicKey().nativeHandle(),
                      message.nativeHandle());
  }

  public int getMessageVersion() {
    return GetVersion(this.handle);
  }

  public IdentityKey getIdentityKey() throws InvalidKeyException {
    return new IdentityKey(GetIdentityKey(this.handle), 0);
  }

  public int getRegistrationId() {
    return GetRegistrationId(this.handle);
  }

  public Optional<Integer> getPreKeyId() {
    int pre_key = GetPreKeyId(this.handle);
    if(pre_key < 0) {
      return Optional.absent();
    } else {
      return Optional.of(pre_key);
    }
  }

  public int getSignedPreKeyId() {
    return GetSignedPreKeyId(this.handle);
  }

  public ECPublicKey getBaseKey() throws InvalidKeyException {
    return new ECPublicKey(GetBaseKey(this.handle));
  }

  public SignalMessage getWhisperMessage() throws InvalidMessageException, LegacyMessageException {
    return new SignalMessage(GetSignalMessage(this.handle));
  }

  @Override
  public byte[] serialize() {
    return GetSerialized(this.handle);
  }

  @Override
  public int getType() {
    return CiphertextMessage.PREKEY_TYPE;
  }

  public long nativeHandle() {
    return this.handle;
  }
}
