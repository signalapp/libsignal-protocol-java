package org.whispersystems.libsignal.fingerprint;


import org.whispersystems.libsignal.IdentityKey;

import java.io.ByteArrayOutputStream;
import java.util.List;

abstract class BaseFingerprintType {

  protected byte[] getLogicalKeyBytes(List<IdentityKey> identityKeys) {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    for (IdentityKey identityKey : identityKeys) {
      byte[] publicKeyBytes = identityKey.getPublicKey().serialize();
      baos.write(publicKeyBytes, 0, publicKeyBytes.length);
    }

    return baos.toByteArray();
  }

}
