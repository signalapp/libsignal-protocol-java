/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state.impl;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.IdentityKeyStore;

import java.util.HashMap;
import java.util.Map;

public class InMemoryIdentityKeyStore implements IdentityKeyStore {

  private final Map<SignalProtocolAddress, IdentityKey> trustedKeys = new HashMap<>();

  private final IdentityKeyPair identityKeyPair;
  private final int             localRegistrationId;

  public InMemoryIdentityKeyStore(IdentityKeyPair identityKeyPair, int localRegistrationId) {
    this.identityKeyPair     = identityKeyPair;
    this.localRegistrationId = localRegistrationId;
  }

  @Override
  public IdentityKeyPair getIdentityKeyPair() {
    return identityKeyPair;
  }

  @Override
  public int getLocalRegistrationId() {
    return localRegistrationId;
  }

  @Override
  public void saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
    trustedKeys.put(address, identityKey);
  }

  @Override
  public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
    IdentityKey trusted = trustedKeys.get(address);
    return (trusted == null || trusted.equals(identityKey));
  }
}
