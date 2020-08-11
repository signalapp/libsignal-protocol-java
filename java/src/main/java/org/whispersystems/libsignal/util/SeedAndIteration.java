/**
 * Copyright (C) 2020 Signal Messenger LLC
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.util;

public class SeedAndIteration {
  static {
       System.loadLibrary("signal_jni");
  }

  private static native long New(byte[] seed, int iteration);
  private static native long Destroy(long handle);

  private static native byte[] GetSeed(long handle);
  private static native int GetIteration(long handle);

  private final long handle;

  public SeedAndIteration(byte[] seed, int iteration) {
    this.handle = New(seed, iteration);
  }

  public SeedAndIteration(long handle) {
    this.handle = handle;
  }

  @Override
  protected void finalize() {
    Destroy(this.handle);
  }

  public int getIteration() {
    return GetIteration(this.handle);
  }

  public byte[] getSeed() {
    return GetSeed(this.handle);
  }
}
