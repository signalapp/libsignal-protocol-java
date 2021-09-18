/*
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.ecc;

import java.security.KeyPair;

public class ECKeyPair {

  private final KeyPair keyPair;

  public ECKeyPair(ECPublicKey publicKey, ECPrivateKey privateKey) {
    this.keyPair = new KeyPair(publicKey,privateKey);
  }

  public KeyPair getKeyPair() {
    return this.keyPair;
  }

  public ECPublicKey getPublicKey() {
    return (ECPublicKey) this.keyPair.getPublic();
  }

  public ECPrivateKey getPrivateKey() {
    return (ECPrivateKey) this.keyPair.getPrivate();
  }
}
