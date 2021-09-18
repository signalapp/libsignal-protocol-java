/*
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */

package org.whispersystems.libsignal.ecc;

import java.security.PublicKey;

public interface ECPublicKey extends PublicKey, Comparable<ECPublicKey> {

  int KEY_SIZE = 33;

  byte[] serialize();

  int getType();
}
