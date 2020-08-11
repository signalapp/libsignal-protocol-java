/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.protocol;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.ByteUtil;

import java.text.ParseException;

public class SenderKeyMessage implements CiphertextMessage {

  private static native long Deserialize(byte[] serialized);
  private static native long New(int keyId, int iteration, byte[] ciphertext, long pkHandle);
  private static native void Destroy(long handle);

  private static native int GetKeyId(long handle);
  private static native int GetIteration(long handle);
  private static native byte[] GetCipherText(long handle);
  private static native byte[] GetSerialized(long handle);
  private static native boolean VerifySignature(long handle, long pkHandle);

  private long handle;

  @Override
  protected void finalize() {
     Destroy(this.handle);
  }

  public SenderKeyMessage(byte[] serialized) throws InvalidMessageException, LegacyMessageException {
    handle = Deserialize(serialized);
  }

  public SenderKeyMessage(int keyId, int iteration, byte[] ciphertext, ECPrivateKey signatureKey) {
    handle = New(keyId, iteration, ciphertext, signatureKey.nativeHandle());
  }

  public int getKeyId() {
    return GetKeyId(this.handle);
  }

  public int getIteration() {
    return GetIteration(this.handle);
  }

  public byte[] getCipherText() {
    return GetCipherText(this.handle);
  }

  public void verifySignature(ECPublicKey signatureKey)
      throws InvalidMessageException
  {
    if(!VerifySignature(this.handle, signatureKey.nativeHandle())) {
      throw new InvalidMessageException("Invalid signature!");
    }
  }

  @Override
  public byte[] serialize() {
    return GetSerialized(this.handle);
  }

  @Override
  public int getType() {
    return CiphertextMessage.SENDERKEY_TYPE;
  }
}
