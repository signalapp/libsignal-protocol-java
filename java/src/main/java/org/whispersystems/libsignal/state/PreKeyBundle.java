/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;

/**
 * A class that contains a remote PreKey and collection
 * of associated items.
 *
 * @author Moxie Marlinspike
 */
public class PreKeyBundle {

  private static native long New(int registrationId, int deviceId, int preKeyId, long preKeyPublicHandle,
                                 int signedPreKeyId, long signedPreKeyPublicHandle, byte[] signedPreKeySignature,
                                 long identityKeyHandle);
  private static native void Destroy(long handle);
  private static native int GetRegistrationId(long handle);
  private static native int GetDeviceId(long handle);
  private static native int GetPreKeyId(long handle);
  private static native int GetSignedPreKeyId(long handle);
  private static native long GetPreKeyPublic(long handle);
  private static native long GetSignedPreKeyPublic(long handle);
  private static native byte[] GetSignedPreKeySignature(long handle);
  private static native long GetIdentityKey(long handle);

  private long handle;

  @Override
  protected void finalize() {
    Destroy(this.handle);
  }

  public PreKeyBundle(int registrationId, int deviceId, int preKeyId, ECPublicKey preKeyPublic,
                      int signedPreKeyId, ECPublicKey signedPreKeyPublic, byte[] signedPreKeySignature,
                      IdentityKey identityKey)
  {
    long preKeyPublicHandle = 0;
    if(preKeyPublic != null) {
      preKeyPublicHandle = preKeyPublic.nativeHandle();
    } else {
      preKeyId = -1;
    }

    this.handle = New(registrationId, deviceId, preKeyId,
                      preKeyPublicHandle,
                      signedPreKeyId,
                      signedPreKeyPublic.nativeHandle(),
                      signedPreKeySignature,
                      identityKey.getPublicKey().nativeHandle());
  }

  /**
   * @return the device ID this PreKey belongs to.
   */
  public int getDeviceId() {
    return GetDeviceId(this.handle);
  }

  /**
   * @return the unique key ID for this PreKey.
   */
  public int getPreKeyId() {
    return GetPreKeyId(this.handle);
  }

  /**
   * @return the public key for this PreKey.
   */
  public ECPublicKey getPreKey() {
    long handle = GetPreKeyPublic(this.handle);
    if(handle != 0) {
      return new ECPublicKey(handle);
    }
    return null;
  }

  /**
   * @return the unique key ID for this signed prekey.
   */
  public int getSignedPreKeyId() {
    return GetSignedPreKeyId(this.handle);
  }

  /**
   * @return the signed prekey for this PreKeyBundle.
   */
  public ECPublicKey getSignedPreKey() {
    return new ECPublicKey(GetSignedPreKeyPublic(this.handle));
  }

  /**
   * @return the signature over the signed  prekey.
   */
  public byte[] getSignedPreKeySignature() {
    return GetSignedPreKeySignature(this.handle);
  }

  /**
   * @return the {@link org.whispersystems.libsignal.IdentityKey} of this PreKeys owner.
   */
  public IdentityKey getIdentityKey() {
    return new IdentityKey(new ECPublicKey(GetIdentityKey(this.handle)));
  }

  /**
   * @return the registration ID associated with this PreKey.
   */
  public int getRegistrationId() {
    return GetRegistrationId(this.handle);
  }
}
