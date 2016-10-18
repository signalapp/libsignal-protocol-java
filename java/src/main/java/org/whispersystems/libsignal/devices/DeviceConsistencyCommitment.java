package org.whispersystems.libsignal.devices;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.protocol.DeviceConsistencyMessage;
import org.whispersystems.libsignal.util.ByteArrayComparator;
import org.whispersystems.libsignal.util.ByteUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class DeviceConsistencyCommitment {

  private static final String VERSION = "DeviceConsistencyCommitment_V0";

  private final int generation;
  private final byte[] serialized;

  public DeviceConsistencyCommitment(int generation, List<IdentityKey> identityKeys) {
    try {
      ArrayList<IdentityKey> sortedIdentityKeys = new ArrayList<>(identityKeys);
      Collections.sort(sortedIdentityKeys, new IdentityKeyComparator());

      MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
      messageDigest.update(VERSION.getBytes());
      messageDigest.update(ByteUtil.intToByteArray(generation));

      for (IdentityKey commitment : sortedIdentityKeys) {
        messageDigest.update(commitment.getPublicKey().serialize());
      }

      this.generation = generation;
      this.serialized = messageDigest.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  public byte[] toByteArray() {
    return serialized;
  }

  public int getGeneration() {
    return generation;
  }

  private static class IdentityKeyComparator extends ByteArrayComparator implements Comparator<IdentityKey> {

    @Override
    public int compare(IdentityKey first, IdentityKey second) {
      return compare(first.getPublicKey().serialize(), second.getPublicKey().serialize());
    }
  }


}
