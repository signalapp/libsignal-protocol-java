/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.ByteUtil;

import javax.crypto.spec.SecretKeySpec;

public class SignalMessage implements CiphertextMessage {

  static {
       System.loadLibrary("signal_jni");
  }

  private static native long nativeDeserialize(byte[] serialized);
  private static native long nativeNew(int messageVersion,
                                 byte[] macKey,
                                 long senderRatchetKeyHandle,
                                 int counter,
                                 int previousCounter,
                                 byte[] ciphertext,
                                 long senderIdentityKeyHandle,
                                 long receiverIdentityKeyHandle);
  private static native void nativeDestroy(long handle);
  private static native byte[] nativeGetSenderRatchetKey(long handle);
  private static native int nativeGetMessageVersion(long handle);
  private static native int nativeGetCounter(long handle);
  private static native byte[] nativeGetBody(long handle);
  private static native byte[] nativeGetSerialized(long handle);
  private static native boolean nativeVerifyMac(long messageHandle,
                                          long senderIdentityKeyHandle, long receiverIdentityKeyHandle, byte[] macKey);

  private final long handle;

  @Override
  protected void finalize() {
     nativeDestroy(this.handle);
  }

  public SignalMessage(byte[] serialized) throws InvalidMessageException, LegacyMessageException {
    handle = nativeDeserialize(serialized);
  }

  public SignalMessage(long handle) {
    this.handle = handle;
  }

  public SignalMessage(int messageVersion, SecretKeySpec macKey, ECPublicKey senderRatchetKey,
                       int counter, int previousCounter, byte[] ciphertext,
                       IdentityKey senderIdentityKey,
                       IdentityKey receiverIdentityKey)
  {
    handle = nativeNew(messageVersion, macKey.getEncoded(), senderRatchetKey.nativeHandle(),
                 counter, previousCounter, ciphertext,
                 senderIdentityKey.getPublicKey().nativeHandle(),
                 receiverIdentityKey.getPublicKey().nativeHandle());
  }

  public ECPublicKey getSenderRatchetKey()  {
    return new ECPublicKey(nativeGetSenderRatchetKey(this.handle));
  }

  public int getMessageVersion() {
    return nativeGetMessageVersion(this.handle);
  }

  public int getCounter() {
    return nativeGetCounter(this.handle);
  }

  public byte[] getBody() {
    return nativeGetBody(this.handle);
  }

  public void verifyMac(IdentityKey senderIdentityKey, IdentityKey receiverIdentityKey, SecretKeySpec macKey)
      throws InvalidMessageException
  {
    if(!nativeVerifyMac(this.handle,
                  senderIdentityKey.getPublicKey().nativeHandle(),
                  receiverIdentityKey.getPublicKey().nativeHandle(),
                  macKey.getEncoded())) {
      throw new InvalidMessageException("Bad Mac!");
    }
  }

  @Override
  public byte[] serialize() {
    return nativeGetSerialized(this.handle);
  }

  @Override
  public int getType() {
    return CiphertextMessage.WHISPER_TYPE;
  }

  public long nativeHandle() {
    return this.handle;
  }

  public static boolean isLegacy(byte[] message) {
    return message != null && message.length >= 1 &&
        ByteUtil.highBitsToInt(message[0]) != CiphertextMessage.CURRENT_VERSION;
  }

}
