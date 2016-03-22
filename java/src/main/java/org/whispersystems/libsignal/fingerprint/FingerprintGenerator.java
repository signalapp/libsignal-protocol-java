package org.whispersystems.libsignal.fingerprint;

import org.whispersystems.libsignal.IdentityKey;

public interface FingerprintGenerator {
  public Fingerprint createFor(String localStableIdentifier, IdentityKey localIdentityKey,
                               String remoteStableIdentifier, IdentityKey remoteIdentityKey);
}
