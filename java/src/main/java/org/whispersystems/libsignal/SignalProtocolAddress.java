/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal;

public class SignalProtocolAddress {

  private static native long New(String name, int device_id);
  private static native long Destroy(long handle);

  private static native String Name(long handle);
  private static native int DeviceId(long handle);

  static {
       System.loadLibrary("signal_jni");
  }

  private final long handle;

  public SignalProtocolAddress(String name, int deviceId) {
    this.handle = New(name, deviceId);
  }

  @Override
  protected void finalize() {
    Destroy(this.handle);
  }

  public String getName() {
    return Name(this.handle);
  }

  public int getDeviceId() {
    return DeviceId(this.handle);
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
