/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.devices.DeviceConsistencySignature;
import org.whispersystems.libsignal.util.ByteArrayComparator;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.IdentityKeyComparator;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class NumericFingerprintGenerator implements FingerprintGenerator {

  private final int iterations;

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
  public NumericFingerprintGenerator(int iterations) {
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
    DisplayableFingerprint displayableFingerprint = new DisplayableFingerprint(iterations,
                                                                               localStableIdentifier,
                                                                               localIdentityKey,
                                                                               remoteStableIdentifier,
                                                                               remoteIdentityKey);

    ScannableFingerprint scannableFingerprint = new ScannableFingerprint(localStableIdentifier, localIdentityKey,
                                                                         remoteStableIdentifier, remoteIdentityKey);

    return new Fingerprint(displayableFingerprint, scannableFingerprint);
  }

  /**
   * Generate a scannable and displayble fingerprint for logical identities that have multiple
   * physical keys.
   *
   * Do not trust the output of this unless you've been through the device consistency process
   * for the provided localIdentityKeys.
   *
   * @param localStableIdentifier The client's "stable" identifier.
   * @param localIdentityKeys The client's collection of physical identity keys.
   * @param remoteStableIdentifier The remote party's "stable" identifier.
   * @param remoteIdentityKeys The remote party's collection of physical identity key.
   * @return A unique fingerprint for this conversation.
   */
  public Fingerprint createFor(String localStableIdentifier, List<IdentityKey> localIdentityKeys,
                               String remoteStableIdentifier, List<IdentityKey> remoteIdentityKeys)
  {
    DisplayableFingerprint displayableFingerprint = new DisplayableFingerprint(iterations,
                                                                               localStableIdentifier,
                                                                               localIdentityKeys,
                                                                               remoteStableIdentifier,
                                                                               remoteIdentityKeys);

    ScannableFingerprint scannableFingerprint = new ScannableFingerprint(localStableIdentifier, localIdentityKeys,
                                                                         remoteStableIdentifier, remoteIdentityKeys);

    return new Fingerprint(displayableFingerprint, scannableFingerprint);
  }


}
