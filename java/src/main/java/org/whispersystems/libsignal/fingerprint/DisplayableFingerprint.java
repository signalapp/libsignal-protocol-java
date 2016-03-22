package org.whispersystems.libsignal.fingerprint;

public class DisplayableFingerprint {

  private final String localFingerprint;
  private final String remoteFingerprint;

  public DisplayableFingerprint(String localFingerprint, String remoteFingerprint) {
    this.localFingerprint  = localFingerprint;
    this.remoteFingerprint = remoteFingerprint;
  }

  public String getDisplayText() {
    if (localFingerprint.compareTo(remoteFingerprint) <= 0) {
      return localFingerprint + remoteFingerprint;
    } else {
      return remoteFingerprint + localFingerprint;
    }
  }
}
