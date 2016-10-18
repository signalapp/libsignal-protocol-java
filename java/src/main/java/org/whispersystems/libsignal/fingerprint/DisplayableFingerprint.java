/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.IdentityKeyComparator;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class DisplayableFingerprint extends BaseFingerprintType {

  private static final int VERSION = 0;

  private final String localFingerprint;
  private final String remoteFingerprint;

  DisplayableFingerprint(int iterations,
                         String localStableIdentifier, final IdentityKey localIdentityKey,
                         String remoteStableIdentifier, final IdentityKey remoteIdentityKey)
  {
    this(iterations, localStableIdentifier,
         new LinkedList<IdentityKey>(){{
           add(localIdentityKey);
         }},
         remoteStableIdentifier,
         new LinkedList<IdentityKey>() {{
           add(remoteIdentityKey);
         }});
  }

  DisplayableFingerprint(int iterations,
                         String localStableIdentifier, List<IdentityKey> localIdentityKeys,
                         String remoteStableIdentifier, List<IdentityKey> remoteIdentityKeys)
  {
    this.localFingerprint  = getDisplayStringFor(iterations, localStableIdentifier, localIdentityKeys);
    this.remoteFingerprint = getDisplayStringFor(iterations, remoteStableIdentifier, remoteIdentityKeys);
  }

  public String getDisplayText() {
    if (localFingerprint.compareTo(remoteFingerprint) <= 0) {
      return localFingerprint + remoteFingerprint;
    } else {
      return remoteFingerprint + localFingerprint;
    }
  }

  private String getDisplayStringFor(int iterations, String stableIdentifier, List<IdentityKey> unsortedIdentityKeys) {
    try {
      ArrayList<IdentityKey> sortedIdentityKeys = new ArrayList<>(unsortedIdentityKeys);
      Collections.sort(sortedIdentityKeys, new IdentityKeyComparator());

      MessageDigest digest    = MessageDigest.getInstance("SHA-512");
      byte[]        publicKey = getLogicalKeyBytes(sortedIdentityKeys);
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
