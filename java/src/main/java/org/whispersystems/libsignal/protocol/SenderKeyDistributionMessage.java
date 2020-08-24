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

  private static native long nativeDeserialize(byte[] data);
  private static native long nativeNew(int id, int iteration, byte[] chainkey, long pkHandle);
  private static native long nativeDestroy(long handle);
  private static native int nativeGetIteration(long handle);
  private static native int nativeGetId(long handle);
  private static native byte[] nativeGetChainKey(long handle);
  private static native byte[] nativeGetSignatureKey(long handle);
  private static native byte[] nativeGetSerialized(long handle);

  private final long handle;

  @Override
  protected void finalize() {
     nativeDestroy(this.handle);
  }

  public SenderKeyDistributionMessage(long handle) {
    this.handle = handle;
  }

  public SenderKeyDistributionMessage(int id, int iteration, byte[] chainKey, ECPublicKey signatureKey) {
    handle = nativeNew(id, iteration, chainKey, signatureKey.nativeHandle());
  }

  public SenderKeyDistributionMessage(byte[] serialized) throws LegacyMessageException, InvalidMessageException {
    handle = nativeDeserialize(serialized);
  }

  @Override
  public byte[] serialize() {
    return nativeGetSerialized(this.handle);
  }

  @Override
  public int getType() {
    return SENDERKEY_DISTRIBUTION_TYPE;
  }

  public int getIteration() {
    return nativeGetIteration(this.handle);
  }

  public byte[] getChainKey() {
    return nativeGetChainKey(this.handle);
  }

  public ECPublicKey getSignatureKey() {
    return new ECPublicKey(nativeGetSignatureKey(this.handle));
  }

  public int getId() {
    return nativeGetId(this.handle);
  }

  public long nativeHandle() {
    return this.handle;
  }
}
