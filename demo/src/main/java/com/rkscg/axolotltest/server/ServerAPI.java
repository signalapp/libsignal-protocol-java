/**
 * @Author Vincent
 */
package com.rkscg.axolotltest.server;

import com.rkscg.axolotltest.ECSignedPublicKey;
import org.whispersystems.libaxolotl.AxolotlAddress;
import org.whispersystems.libaxolotl.IdentityKey;
import org.whispersystems.libaxolotl.ecc.ECPublicKey;
import org.whispersystems.libaxolotl.protocol.CiphertextMessage;
import org.whispersystems.libaxolotl.state.PreKeyBundle;
import org.whispersystems.libaxolotl.util.KeyHelper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ServerAPI {

    // Pretend this is secure
    static final Object USER_DATA_LOCK = new Object();
    private static Map<String, UserInfo> userData = new HashMap<String, UserInfo>();

    public static int register(AxolotlAddress address, IdentityKey identityKey, Map<Integer, ECPublicKey> preKeys, int signedPreKeyId, ECPublicKey signedPreKey, byte[] signedPreKeySignature) {
        synchronized (USER_DATA_LOCK) {
            int registrationId  = KeyHelper.generateRegistrationId(false);
            userData.put(address.getName(), new UserInfo(identityKey, registrationId, address.getDeviceId(), preKeys, signedPreKeyId, signedPreKey, signedPreKeySignature));
            return registrationId;
        }
    }

    public static PreKeyBundle getPreKeyBundle(String name) {
        System.out.println("Server - PreKey bundle was requested for " + name);
        synchronized (USER_DATA_LOCK) {
            return userData.get(name).getPreKeyBundle();
        }
    }

    public static List<AxolotlAddress> getContacts(String name) {
        synchronized (USER_DATA_LOCK) {
            return userData.entrySet().stream()
                    .filter(entry -> !entry.getKey().equalsIgnoreCase(name))
                    .map(entry -> new AxolotlAddress(entry.getKey(), entry.getValue().getDeviceId()))
                    .collect(Collectors.toList());
        }
    }

    // Also pretends this is secure
    static final Object MESSAGE_LOCK = new Object();
    private static Map<String, Map<String, List<byte[]>>> inTransitMessages = new HashMap<>();

    public static void sendMessage(String from, String to, byte[] message) {
        System.out.println("Server - A message was sent from " + from + " to " + to);
        synchronized (MESSAGE_LOCK) {
            if (!inTransitMessages.containsKey(to)) {
                Map<String, List<byte[]>> bundle = new HashMap<>();

                List<byte[]> messageList = new ArrayList<>();
                messageList.add(message);

                bundle.put(from, messageList);

                inTransitMessages.put(to, bundle);
            } else {
                Map<String, List<byte[]>> bundle = inTransitMessages.get(to);

                if (!bundle.containsKey(from)) {
                    List<byte[]> messageList = new ArrayList<>();
                    messageList.add(message);

                    bundle.put(from, messageList);
                } else {
                    bundle.get(from).add(message);
                }
            }
        }
    }

    public static Map<String, List<byte[]>> retreiveMessages(String name) {
        synchronized (MESSAGE_LOCK) {
            if (inTransitMessages.containsKey(name)) {
                Map<String, List<byte[]>> bundle = inTransitMessages.get(name);
                inTransitMessages.remove(name);

                int messageCount = 0;
                for (Map.Entry<String, List<byte[]>> subbundle : bundle.entrySet()) {
                    messageCount += subbundle.getValue().size();
                }

                System.out.println("Server - " + name + " retrieved " + messageCount + " messages from " + bundle.size() + " contacts");
                return bundle;
            }

            return new HashMap<>();
        }
    }
}
