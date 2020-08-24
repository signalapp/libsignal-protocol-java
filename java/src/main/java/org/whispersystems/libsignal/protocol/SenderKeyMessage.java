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

  private static native long nativeDeserialize(byte[] serialized);
  private static native long nativeNew(int keyId, int iteration, byte[] ciphertext, long pkHandle);
  private static native void nativeDestroy(long handle);

  private static native int nativeGetKeyId(long handle);
  private static native int nativeGetIteration(long handle);
  private static native byte[] nativeGetCipherText(long handle);
  private static native byte[] nativeGetSerialized(long handle);
  private static native boolean nativeVerifySignature(long handle, long pkHandle);

  private long handle;

  @Override
  protected void finalize() {
     nativeDestroy(this.handle);
  }

  public SenderKeyMessage(byte[] serialized) throws InvalidMessageException, LegacyMessageException {
    handle = nativeDeserialize(serialized);
  }

  public SenderKeyMessage(int keyId, int iteration, byte[] ciphertext, ECPrivateKey signatureKey) {
    handle = nativeNew(keyId, iteration, ciphertext, signatureKey.nativeHandle());
  }

  public int getKeyId() {
    return nativeGetKeyId(this.handle);
  }

  public int getIteration() {
    return nativeGetIteration(this.handle);
  }

  public byte[] getCipherText() {
    return nativeGetCipherText(this.handle);
  }

  public void verifySignature(ECPublicKey signatureKey)
      throws InvalidMessageException
  {
    if(!nativeVerifySignature(this.handle, signatureKey.nativeHandle())) {
      throw new InvalidMessageException("Invalid signature!");
    }
  }

  @Override
  public byte[] serialize() {
    return nativeGetSerialized(this.handle);
  }

  @Override
  public int getType() {
    return CiphertextMessage.SENDERKEY_TYPE;
  }
}
