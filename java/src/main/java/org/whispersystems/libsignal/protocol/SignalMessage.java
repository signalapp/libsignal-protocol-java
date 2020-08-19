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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SignalMessage implements CiphertextMessage {

  static {
       System.loadLibrary("signal_jni");
  }

  private static native long Deserialize(byte[] serialized);
  private static native long New(int messageVersion,
                                 byte[] macKey,
                                 long senderRatchetKeyHandle,
                                 int counter,
                                 int previousCounter,
                                 byte[] ciphertext,
                                 long senderIdentityKeyHandle,
                                 long receiverIdentityKeyHandle);
  private static native void Destroy(long handle);
  private static native byte[] GetSenderRatchetKey(long handle);
  private static native int GetMessageVersion(long handle);
  private static native int GetCounter(long handle);
  private static native byte[] GetBody(long handle);
  private static native byte[] GetSerialized(long handle);
  private static native boolean VerifyMac(long messageHandle,
                                          long senderIdentityKeyHandle, long receiverIdentityKeyHandle, byte[] macKey);

  private final long handle;

  @Override
  protected void finalize() {
     Destroy(this.handle);
  }

  public SignalMessage(byte[] serialized) throws InvalidMessageException, LegacyMessageException {
    handle = Deserialize(serialized);
  }

  public SignalMessage(long handle) {
    this.handle = handle;
  }

  public SignalMessage(int messageVersion, SecretKeySpec macKey, ECPublicKey senderRatchetKey,
                       int counter, int previousCounter, byte[] ciphertext,
                       IdentityKey senderIdentityKey,
                       IdentityKey receiverIdentityKey)
  {
    handle = New(messageVersion, macKey.getEncoded(), senderRatchetKey.nativeHandle(),
                 counter, previousCounter, ciphertext,
                 senderIdentityKey.getPublicKey().nativeHandle(),
                 receiverIdentityKey.getPublicKey().nativeHandle());
  }

  public ECPublicKey getSenderRatchetKey()  {
    return new ECPublicKey(GetSenderRatchetKey(this.handle));
  }

  public int getMessageVersion() {
    return GetMessageVersion(this.handle);
  }

  public int getCounter() {
    return GetCounter(this.handle);
  }

  public byte[] getBody() {
    return GetBody(this.handle);
  }

  public void verifyMac(IdentityKey senderIdentityKey, IdentityKey receiverIdentityKey, SecretKeySpec macKey)
      throws InvalidMessageException
  {
    if(!VerifyMac(this.handle,
                  senderIdentityKey.getPublicKey().nativeHandle(),
                  receiverIdentityKey.getPublicKey().nativeHandle(),
                  macKey.getEncoded())) {
      throw new InvalidMessageException("Bad Mac!");
    }
  }

  @Override
  public byte[] serialize() {
    return GetSerialized(this.handle);
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
