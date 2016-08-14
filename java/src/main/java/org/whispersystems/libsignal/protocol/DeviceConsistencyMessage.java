package org.whispersystems.libsignal.protocol;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.devices.DeviceConsistencyCommitment;
import org.whispersystems.libsignal.devices.DeviceConsistencySignature;
import org.whispersystems.libsignal.ecc.Curve;

public class DeviceConsistencyMessage {

  private final DeviceConsistencySignature signature;
  private final byte[]                     serialized;

  public DeviceConsistencyMessage(DeviceConsistencyCommitment commitment, IdentityKeyPair identityKeyPair) {
    try {
      this.signature  = new DeviceConsistencySignature(Curve.calculateUniqueSignature(identityKeyPair.getPrivateKey(), commitment.toByteArray()));
      this.serialized = SignalProtos.DeviceConsistencyCodeMessage.newBuilder()
                                                                  .setGeneration(commitment.getGeneration())
                                                                  .setSignature(ByteString.copyFrom(signature.toByteArray()))
                                                                  .build()
                                                                  .toByteArray();
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  public DeviceConsistencyMessage(DeviceConsistencyCommitment commitment, byte[] serialized, IdentityKey identityKey) throws InvalidMessageException {
    try {
      SignalProtos.DeviceConsistencyCodeMessage message = SignalProtos.DeviceConsistencyCodeMessage.parseFrom(serialized);

      if (!Curve.verifyUniqueSignature(identityKey.getPublicKey(), commitment.toByteArray(), message.getSignature().toByteArray())) {
        throw new InvalidMessageException("Bad signature!");
      }

      this.signature  = new DeviceConsistencySignature(message.getSignature().toByteArray());
      this.serialized = serialized;
    } catch (InvalidProtocolBufferException | InvalidKeyException e) {
      throw new InvalidMessageException(e);
    }
  }

  public byte[] getSerialized() {
    return serialized;
  }

  public DeviceConsistencySignature getSignature() {
    return signature;
  }
}
