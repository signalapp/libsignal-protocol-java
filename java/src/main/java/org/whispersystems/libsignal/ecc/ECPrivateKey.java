/*
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.ecc;

import java.security.PrivateKey;

public interface ECPrivateKey extends PrivateKey {
  byte[] serialize();
  int getType();
}
