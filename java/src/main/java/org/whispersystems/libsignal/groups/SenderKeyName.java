/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.groups;

import org.whispersystems.libsignal.SignalProtocolAddress;

/**
 * A representation of a (groupId + senderId + deviceId) tuple.
 */
public class SenderKeyName {

  private static native long nativeNew(String groupid, String senderName, int senderDeviceId);
  private static native void nativeDestroy(long handle);
  private static native String nativeGetSenderName(long handle);
  private static native int nativeGetSenderDeviceId(long handle);
  private static native String nativeGetGroupId(long handle);

  static {
       System.loadLibrary("signal_jni");
  }

  private long handle;

  public SenderKeyName(String groupId, SignalProtocolAddress sender) {
    this.handle = nativeNew(groupId, sender.getName(), sender.getDeviceId());
  }

  public SenderKeyName(String groupId, String senderName, int senderDeviceId) {
    this.handle = nativeNew(groupId, senderName, senderDeviceId);
  }

  @Override
  protected void finalize() {
    nativeDestroy(this.handle);
  }

  public String getGroupId() {
    return nativeGetGroupId(this.handle);
  }

  public SignalProtocolAddress getSender() {
    return new SignalProtocolAddress(nativeGetSenderName(this.handle), nativeGetSenderDeviceId(this.handle));
  }

  public String serialize() {
    SignalProtocolAddress sender = this.getSender();
    return this.getGroupId() + "::" + sender.getName() + "::" + String.valueOf(sender.getDeviceId());
  }

  @Override
  public boolean equals(Object other) {
    if (other == null)                     return false;
    if (!(other instanceof SenderKeyName)) return false;

    SenderKeyName that = (SenderKeyName)other;

    return
       this.getGroupId().equals(that.getGroupId()) &&
       this.getSender().equals(that.getSender());
  }

  @Override
  public int hashCode() {
    return this.serialize().hashCode();
  }

  public long nativeHandle() {
    return this.handle;
  }

}
