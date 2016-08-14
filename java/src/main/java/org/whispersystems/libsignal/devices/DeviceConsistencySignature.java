package org.whispersystems.libsignal.devices;

public class DeviceConsistencySignature {

  private byte[] serialized;

  public DeviceConsistencySignature(byte[] serialized) {
    this.serialized = serialized;
  }

  public byte[] getRevealBytes() {
    byte[] reveal = new byte[32];
    System.arraycopy(serialized, 0, reveal, 0, reveal.length);
    return reveal;
  }

  public byte[] toByteArray() {
    return serialized;
  }
}
