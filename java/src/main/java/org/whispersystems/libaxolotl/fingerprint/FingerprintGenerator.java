package org.whispersystems.libaxolotl.fingerprint;

import org.whispersystems.libaxolotl.IdentityKey;

public interface FingerprintGenerator {
  public Fingerprint createFor(String localStableIdentifier, IdentityKey localIdentityKey,
                               String remoteStableIdentifier, IdentityKey remoteIdentityKey);
}
