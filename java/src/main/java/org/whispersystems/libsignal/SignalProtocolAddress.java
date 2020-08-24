/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal;

public class SignalProtocolAddress {

  private static native long nativeNew(String name, int device_id);
  private static native long nativeDestroy(long handle);

  private static native String nativeName(long handle);
  private static native int nativeDeviceId(long handle);

  static {
       System.loadLibrary("signal_jni");
  }

  private final long handle;

  public SignalProtocolAddress(String name, int deviceId) {
    this.handle = nativeNew(name, deviceId);
  }

  @Override
  protected void finalize() {
    nativeDestroy(this.handle);
  }

  public String getName() {
    return nativeName(this.handle);
  }

  public int getDeviceId() {
    return nativeDeviceId(this.handle);
  }

  @Override
  public String toString() {
    return getName() + ":" + getDeviceId();
  }

  @Override
  public boolean equals(Object other) {
    if (other == null)                       return false;
    if (!(other instanceof SignalProtocolAddress)) return false;

    SignalProtocolAddress that = (SignalProtocolAddress)other;
    return this.getName().equals(that.getName()) && this.getDeviceId() == that.getDeviceId();
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  public long nativeHandle() {
    return this.handle;
  }
}
