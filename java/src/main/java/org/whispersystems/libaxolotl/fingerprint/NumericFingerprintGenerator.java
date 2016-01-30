package org.whispersystems.libaxolotl.fingerprint;

import org.whispersystems.libaxolotl.IdentityKey;
import org.whispersystems.libaxolotl.util.ByteUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class NumericFingerprintGenerator implements FingerprintGenerator {

  private static final int VERSION = 0;

  private final long iterations;

  /**
   * Construct a fingerprint generator for 60 digit numerics.
   *
   * @param iterations The number of internal iterations to perform in the process of
   *                   generating a fingerprint. This needs to be constant, and synchronized
   *                   across all clients.
   *
   *                   The higher the iteration count, the higher the security level:
   *
   *                   - 1024 ~ 109.7 bits
   *                   - 1400 > 110 bits
   *                   - 5200 > 112 bits
   */
  public NumericFingerprintGenerator(long iterations) {
    this.iterations = iterations;
  }

  /**
   * Generate a scannable and displayble fingerprint.
   *
   * @param localStableIdentifier The client's "stable" identifier.
   * @param localIdentityKey The client's identity key.
   * @param remoteStableIdentifier The remote party's "stable" identifier.
   * @param remoteIdentityKey The remote party's identity key.
   * @return A unique fingerprint for this conversation.
   */
  @Override
  public Fingerprint createFor(String localStableIdentifier, IdentityKey localIdentityKey,
                               String remoteStableIdentifier, IdentityKey remoteIdentityKey)
  {
    DisplayableFingerprint displayableFingerprint = new DisplayableFingerprint(getDisplayStringFor(localStableIdentifier, localIdentityKey),
                                                                               getDisplayStringFor(remoteStableIdentifier, remoteIdentityKey));

    ScannableFingerprint scannableFingerprint = new ScannableFingerprint(VERSION,
                                                                         localStableIdentifier, localIdentityKey,
                                                                         remoteStableIdentifier, remoteIdentityKey);

    return new Fingerprint(displayableFingerprint, scannableFingerprint);
  }

  private String getDisplayStringFor(String stableIdentifier, IdentityKey identityKey) {
    try {
      MessageDigest digest    = MessageDigest.getInstance("SHA-512");
      byte[]        publicKey = identityKey.getPublicKey().serialize();
      byte[]        hash      = ByteUtil.combine(ByteUtil.shortToByteArray(VERSION),
                                                 publicKey, stableIdentifier.getBytes());

      for (int i=0;i<iterations;i++) {
        digest.update(hash);
        hash = digest.digest(publicKey);
      }

      return getEncodedChunk(hash, 0) +
          getEncodedChunk(hash, 5) +
          getEncodedChunk(hash, 10) +
          getEncodedChunk(hash, 15) +
          getEncodedChunk(hash, 20) +
          getEncodedChunk(hash, 25);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  private String getEncodedChunk(byte[] hash, int offset) {
    long chunk = ByteUtil.byteArray5ToLong(hash, offset) % 100000;
    return String.format("%05d", chunk);
  }

}
