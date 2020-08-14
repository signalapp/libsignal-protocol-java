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
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.ByteUtil;

public class SenderKeyDistributionMessage implements CiphertextMessage {

  private static native long Deserialize(byte[] data);
  private static native long New(int id, int iteration, byte[] chainkey, long pkHandle);
  private static native long Destroy(long handle);
  private static native int GetIteration(long handle);
  private static native int GetId(long handle);
  private static native byte[] GetChainKey(long handle);
  private static native byte[] GetSignatureKey(long handle);
  private static native byte[] GetSerialized(long handle);

  private final long handle;

  @Override
  protected void finalize() {
     Destroy(this.handle);
  }

  public SenderKeyDistributionMessage(long handle) {
    this.handle = handle;
  }

  public SenderKeyDistributionMessage(int id, int iteration, byte[] chainKey, ECPublicKey signatureKey) {
    handle = New(id, iteration, chainKey, signatureKey.nativeHandle());
  }

  public SenderKeyDistributionMessage(byte[] serialized) throws LegacyMessageException, InvalidMessageException {
    handle = Deserialize(serialized);
  }

  @Override
  public byte[] serialize() {
    return GetSerialized(this.handle);
  }

  @Override
  public int getType() {
    return SENDERKEY_DISTRIBUTION_TYPE;
  }

  public int getIteration() {
    return GetIteration(this.handle);
  }

  public byte[] getChainKey() {
    return GetChainKey(this.handle);
  }

  public ECPublicKey getSignatureKey() {
    return new ECPublicKey(GetSignatureKey(this.handle));
  }

  public int getId() {
    return GetId(this.handle);
  }

  public long nativeHandle() {
    return this.handle;
  }
}
