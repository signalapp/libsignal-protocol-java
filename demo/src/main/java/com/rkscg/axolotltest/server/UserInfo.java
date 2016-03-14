/**
 * @Author Vincent
 */
package com.rkscg.axolotltest.server;

import com.rkscg.axolotltest.ECSignedPublicKey;
import org.whispersystems.libaxolotl.AxolotlAddress;
import org.whispersystems.libaxolotl.IdentityKey;
import org.whispersystems.libaxolotl.ecc.ECPublicKey;
import org.whispersystems.libaxolotl.state.PreKeyBundle;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class UserInfo {
    private IdentityKey identityKey;
    private int registrationId;
    private int deviceId;
    private Map<Integer, ECPublicKey> preKeys;
    private int signedPreKeyId;
    private ECPublicKey signedPreKey;
    private byte[] signedPreKeySignature;

    public UserInfo(IdentityKey identityKey, int registrationId, int deviceId, Map<Integer, ECPublicKey> preKeys, int signedPreKeyId, ECPublicKey signedPreKey, byte[] signedPreKeySignature) {

        this.identityKey = identityKey;
        this.registrationId = registrationId;
        this.deviceId = deviceId;
        this.preKeys = preKeys;
        this.signedPreKeyId = signedPreKeyId;
        this.signedPreKey = signedPreKey;
        this.signedPreKeySignature = signedPreKeySignature;
    }

    public PreKeyBundle getPreKeyBundle() {
        Random        random    = new Random();

        List<Integer> preKeyIds = new ArrayList<Integer>(preKeys.keySet());
        Integer       preKeyId  = preKeyIds.get( random.nextInt(preKeyIds.size()) );
        ECPublicKey   preKey    = preKeys.get(preKeyId);

        return new PreKeyBundle(this.registrationId,
                this.deviceId,
                preKeyId,
                preKey,
                this.signedPreKeyId,
                this.signedPreKey,
                this.signedPreKeySignature,
                this.identityKey);
    }

    public int getDeviceId() {
        return this.deviceId;
    }
}
