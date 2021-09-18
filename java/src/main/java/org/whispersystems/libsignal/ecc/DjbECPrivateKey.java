/*
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.ecc;

public class DjbECPrivateKey implements ECPrivateKey {

  private final byte[] privateKey;

  DjbECPrivateKey(byte[] privateKey) {
    this.privateKey = privateKey;
  }

  @Override
  public String getAlgorithm() {
    return "Curve25519";
  }

  @Override
  public String getFormat() {
    return "RAW";
  }

  @Override
  public byte[] getEncoded() {
    return this.privateKey;
  }

  @Override
  public byte[] serialize() {
    return this.privateKey;
  }

  @Override
  public int getType() {
    return Curve.DJB_TYPE;
  }

}
