/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.fingerprint.FingerprintProtos.CombinedFingerprint;
import org.whispersystems.libsignal.fingerprint.FingerprintProtos.FingerprintData;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class ScannableFingerprint extends BaseFingerprintType {

  private static final int VERSION = 0;

  private final CombinedFingerprint combinedFingerprint;

  ScannableFingerprint(String localStableIdentifier, IdentityKey localIdentityKey,
                       String remoteStableIdentifier, IdentityKey remoteIdentityKey)
  {
    this.combinedFingerprint = initializeCombinedFingerprint(localStableIdentifier, localIdentityKey.serialize(),
                                                             remoteStableIdentifier, remoteIdentityKey.serialize());
  }

  ScannableFingerprint(String localStableIdentifier, List<IdentityKey> localIdentityKeys,
                       String remoteStableIdentifier, List<IdentityKey> remoteIdentityKeys)
  {
    try {
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");

      byte[] localIdentityLogicalKey  = messageDigest.digest(getLogicalKeyBytes(localIdentityKeys));
      byte[] remoteIdentityLogicalKey = messageDigest.digest(getLogicalKeyBytes(remoteIdentityKeys));


      this.combinedFingerprint = initializeCombinedFingerprint(localStableIdentifier, localIdentityLogicalKey,
                                                               remoteStableIdentifier, remoteIdentityLogicalKey);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  /**
   * @return A byte string to be displayed in a QR code.
   */
  public byte[] getSerialized() {
    return combinedFingerprint.toByteArray();
  }

  /**
   * Compare a scanned QR code with what we expect.
   *
   * @param scannedFingerprintData The scanned data
   * @return True if matching, otehrwise false.
   * @throws FingerprintVersionMismatchException if the scanned fingerprint is the wrong version.
   * @throws FingerprintIdentifierMismatchException if the scanned fingerprint is for the wrong stable identifier.
   */
  public boolean compareTo(byte[] scannedFingerprintData)
      throws FingerprintVersionMismatchException,
             FingerprintIdentifierMismatchException,
             FingerprintParsingException
  {
    try {
      CombinedFingerprint scannedFingerprint = CombinedFingerprint.parseFrom(scannedFingerprintData);

      if (!scannedFingerprint.hasRemoteFingerprint() || !scannedFingerprint.hasLocalFingerprint() ||
          !scannedFingerprint.hasVersion() || scannedFingerprint.getVersion() != combinedFingerprint.getVersion())
      {
        throw new FingerprintVersionMismatchException();
      }

      if (!combinedFingerprint.getLocalFingerprint().getIdentifier().equals(scannedFingerprint.getRemoteFingerprint().getIdentifier()) ||
          !combinedFingerprint.getRemoteFingerprint().getIdentifier().equals(scannedFingerprint.getLocalFingerprint().getIdentifier()))
      {
        throw new FingerprintIdentifierMismatchException(new String(combinedFingerprint.getLocalFingerprint().getIdentifier().toByteArray()),
                                                         new String(combinedFingerprint.getRemoteFingerprint().getIdentifier().toByteArray()),
                                                         new String(scannedFingerprint.getLocalFingerprint().getIdentifier().toByteArray()),
                                                         new String(scannedFingerprint.getRemoteFingerprint().getIdentifier().toByteArray()));
      }

      return MessageDigest.isEqual(combinedFingerprint.getLocalFingerprint().toByteArray(), scannedFingerprint.getRemoteFingerprint().toByteArray()) &&
             MessageDigest.isEqual(combinedFingerprint.getRemoteFingerprint().toByteArray(), scannedFingerprint.getLocalFingerprint().toByteArray());
    } catch (InvalidProtocolBufferException e) {
      throw new FingerprintParsingException(e);
    }
  }

  private CombinedFingerprint initializeCombinedFingerprint(String localStableIdentifier, byte[] localIdentityKeyBytes,
                                                            String remoteStableIdentifier, byte[] remoteIdentityKeyBytes)
  {
    return CombinedFingerprint.newBuilder()
                              .setVersion(VERSION)
                              .setLocalFingerprint(FingerprintData.newBuilder()
                                                                  .setIdentifier(ByteString.copyFrom(localStableIdentifier.getBytes()))
                                                                  .setPublicKey(ByteString.copyFrom(localIdentityKeyBytes)))
                              .setRemoteFingerprint(FingerprintData.newBuilder()
                                                                   .setIdentifier(ByteString.copyFrom(remoteStableIdentifier.getBytes()))
                                                                   .setPublicKey(ByteString.copyFrom(remoteIdentityKeyBytes)))
                              .build();
  }
}
