/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

import org.whispersystems.libsignal.util.ByteUtil;

public class DisplayableFingerprint {

  private static native String nativeFormat(byte[] localFingerprint, byte[] remoteFingerprint);

  private String displayString;

  DisplayableFingerprint(byte[] localFingerprint, byte[] remoteFingerprint) {
    this.displayString = nativeFormat(localFingerprint, remoteFingerprint);
  }

  DisplayableFingerprint(String displayString) {
    this.displayString = displayString;
  }

  public String getDisplayText() {
    return this.displayString;
  }

}
