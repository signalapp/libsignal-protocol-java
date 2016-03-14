/**
 * @Author Vincent
 */
package com.rkscg.axolotltest.client;

import com.github.javafaker.Faker;
import com.rkscg.axolotltest.server.ServerAPI;
import org.whispersystems.libaxolotl.*;
import org.whispersystems.libaxolotl.ecc.ECPublicKey;
import org.whispersystems.libaxolotl.groups.GroupCipher;
import org.whispersystems.libaxolotl.groups.GroupSessionBuilder;
import org.whispersystems.libaxolotl.groups.SenderKeyName;
import org.whispersystems.libaxolotl.protocol.PreKeyWhisperMessage;
import org.whispersystems.libaxolotl.protocol.SenderKeyDistributionMessage;
import org.whispersystems.libaxolotl.protocol.WhisperMessage;
import org.whispersystems.libaxolotl.state.PreKeyBundle;
import org.whispersystems.libaxolotl.state.PreKeyRecord;
import org.whispersystems.libaxolotl.state.SignedPreKeyRecord;
import org.whispersystems.libaxolotl.state.impl.InMemoryAxolotlStore;
import org.whispersystems.libaxolotl.util.KeyHelper;
import org.whispersystems.libaxolotl.util.Medium;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

public class ClientRunnable implements Runnable {
    private Faker  faker  = new Faker();
    private Random random = new Random();

    private AxolotlAddress address;
    private InMemoryAxolotlStore store;

    //Sets up a client based on provided identity
    public ClientRunnable(String name, int deviceId) throws InvalidKeyException {

        System.out.println(name + " - Starting with device " + deviceId);

        this.address = new AxolotlAddress(name, deviceId);

        //Generate some keys for usage. Usually this would be loaded form storage at least in part.
        IdentityKeyPair    identityKeyPair = KeyHelper.generateIdentityKeyPair();
        System.out.println(name + " - Identity fingerprints " + identityKeyPair.getPublicKey().getFingerprint());

        List<PreKeyRecord> preKeys         = KeyHelper.generatePreKeys(new Random().nextInt(Medium.MAX_VALUE-101), 100);
        PreKeyRecord       lastResortKey   = KeyHelper.generateLastResortPreKey();
        SignedPreKeyRecord signedPreKey    = KeyHelper.generateSignedPreKey(identityKeyPair, new Random().nextInt(Medium.MAX_VALUE-1));
        System.out.println(name + " - Generated 101 preKey and 1 signedPreKey");

        Map<Integer, ECPublicKey> publicPreKeys = preKeys.stream().collect(Collectors.toMap(PreKeyRecord::getId, item -> item.getKeyPair().getPublicKey()));

        //Register with the server, storing all our public preKeys and some identifying data to get registration ID.
        int registrationId = ServerAPI.register(this.address, identityKeyPair.getPublicKey(), publicPreKeys, signedPreKey.getId(), signedPreKey.getKeyPair().getPublicKey(), signedPreKey.getSignature());
        System.out.println(name + " - Registration with server successful. ID " + registrationId);

        //Store all the generated keys to axolotlMemoryStore (aggregate of preKeyStore, SessionStore, IdentityStore and signedPreKeyStore)
        this.store = new InMemoryAxolotlStore(identityKeyPair, registrationId);
        this.store.storeSignedPreKey(signedPreKey.getId(), signedPreKey);
        for (PreKeyRecord record : preKeys) {
            this.store.storePreKey(record.getId(), record);
        }
        this.store.storePreKey(lastResortKey.getId(), lastResortKey);

        System.out.println(name + " - Local storage completed, ready for action");
    }

    //We start the actual session
    public void run() {

        System.out.println(this.address.getName() + " - Attempting to retrieve contacts using service");
        List<AxolotlAddress> contacts = ServerAPI.getContacts(this.address.getName());;

        while (contacts == null || contacts.size() == 0) {

            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

            System.out.println(this.address.getName() + " - Re-Attempting to retrieve contacts using service");
            contacts = ServerAPI.getContacts(this.address.getName());
        }

        try {
            //Are we dealing with only 1 contact or a group?
            if (contacts.size() == 1) {
                runSingleSession(contacts.get(0));
            } else {
                runGroupSession(contacts);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void runSingleSession(AxolotlAddress contact) throws UntrustedIdentityException, InvalidKeyException, UnsupportedEncodingException, InvalidVersionException, InvalidMessageException, DuplicateMessageException, LegacyMessageException, InvalidKeyIdException, NoSessionException, InterruptedException {

        SessionCipher sessionCipher;

        //Let's assume the lowest deviceID gets to initiate conversation
        if (this.address.getDeviceId() < contact.getDeviceId()) {
            System.out.println(this.address.getName() + " - Single contact, will attempt to initiate session with " + contact.getName());

            // Instantiate a SessionBuilder for a remote recipientId + deviceId tuple.
            SessionBuilder sessionBuilder = new SessionBuilder(this.store, contact);

            // Retrieve PreKey of contact from server
            PreKeyBundle retrievedPreKey = ServerAPI.getPreKeyBundle(contact.getName());

            // Build a session with a PreKey retrieved from the server.
            sessionBuilder.process(retrievedPreKey);

            sessionCipher = new SessionCipher(this.store, contact);

            //Send a message to contact which is automatically a PreKeyWhisper message by default as we have no existing session

            ServerAPI.sendMessage(this.address.getName(), contact.getName(), prepareMessage(contact.getName(), faker.lorem().sentence(), sessionCipher));
        } else {

            System.out.println(this.address.getName() + " - Single contact, will wait for session initiation from " + contact.getName());

            //Let's poll (pretend this is push notification-triggered) for session initiation from other contact
            //TODO merge into basic polling to initiate sessions as needed
            do {
                Map<String, List<byte[]>> bundle = ServerAPI.retreiveMessages(this.address.getName());
                if (bundle.containsKey(contact.getName())) {

                    //Get message for the only contact we even know about
                    List<byte[]> messages = bundle.get(contact.getName());
                    PreKeyWhisperMessage incomingMessage = new PreKeyWhisperMessage(messages.get(0));

                    //Creating the sessionCipher with a PreKeyWhisper automatically bootstraps the session
                    sessionCipher = new SessionCipher(this.store, contact);

                    byte[]        plaintext     = sessionCipher.decrypt(incomingMessage);
                    System.out.println(this.address.getName() + " <- " + contact.getName() + ": " + new String(plaintext, StandardCharsets.UTF_8));

                    messages.remove(0);

                    //If more stacked messages, process to ratchet the cipher
                    for (byte[] message : messages) {
                        byte[] text = sessionCipher.decrypt(new WhisperMessage(message));
                        System.out.println(this.address.getName() + " <- " + contact.getName() + ": " + new String(text, StandardCharsets.UTF_8));
                    }

                    break;
                }

                //Give it a bit of latency between checks
                Thread.sleep(100);
            } while (true);
        }

        // Let's now play the game of sending random messages,
        // at random times, a random number of times before checking
        // for random amounts of time
        List<byte[]> pendingMessages = new ArrayList<>();
        do {
            boolean active    = random.nextBoolean();
            boolean connected = random.nextBoolean();

            //User is actively sending messages, internet might be bad.
            if (active) {
                //Send a few messages messages
                for (int i = 0; i < random.nextInt(4); i++) {

                    pendingMessages.add(prepareMessage(contact.getName(), faker.lorem().sentence(), sessionCipher));

                    Thread.sleep(random.nextInt(3) * 200);
                }
            }

            //User has internet connectivity, sends and receive pending messaged
            if (connected) {

                //Send
                for (byte[] message : pendingMessages) {
                    ServerAPI.sendMessage(this.address.getName(), contact.getName(), message);
                }
                pendingMessages.clear();

                //Receive
                Map<String, List<byte[]>> bundle = ServerAPI.retreiveMessages(this.address.getName());
                if (bundle.containsKey(contact.getName())) {
                    List<byte[]> messages = bundle.get(contact.getName());

                    for (byte[] message : messages) {
                        WhisperMessage whisper = null;
                        try {
                            whisper = new WhisperMessage(message);
                            byte[] text = sessionCipher.decrypt(whisper);
                            System.out.println(this.address.getName() + " <- " + contact.getName() + ": " + new String(text, StandardCharsets.UTF_8));
                        } catch (Exception e) {
                            System.out.println("ERROR - " + this.address.getName() + " cannot decrypt message. Received " + Arrays.toString(message));

                            //Purely for debug purposes... seems counter is empty mostly?
                            try {
                                whisper = new WhisperMessage(message);
                            } catch (Exception e1) {
                            }

                            if (whisper != null) {
                                System.out.println("ERROR - Counter: " + whisper.getCounter()
                                        + " Version: " + whisper.getMessageVersion()
                                        + " Ratchet key: " + whisper.getSenderRatchetKey()
                                        + " Type: " + whisper.getType());
                            }
                        }
                    }
                }
            }

            Thread.sleep(random.nextInt(3) * 1000);
        } while (true);
    }

    private void runGroupSession(List<AxolotlAddress> contacts) throws InvalidMessageException, LegacyMessageException, DuplicateMessageException, NoSessionException, InterruptedException {
        GroupCipher encryptGroupCipher = null;
        Map<String, GroupCipher> decryptGroupCiphers = new HashMap<>();
        InMemorySenderKeyStore senderStore = new InMemorySenderKeyStore();
        GroupSessionBuilder sessionBuilder = new GroupSessionBuilder(senderStore);
        String groupName = "About this project...";

        //Let's assume the lowest deviceID gets to initiate conversation
        if (this.address.getDeviceId() < contacts.stream().min(Comparator.comparing(AxolotlAddress::getDeviceId)).get().getDeviceId()) {
            System.out.println(this.address.getName() + " - Multiple contacts, will attempt to initiate group session with all other existing contacts");

            // Instantiate a Sender's key representing the group from ourselves
            SenderKeyName senderKeyName = new SenderKeyName(groupName, this.address);

            //We build the group session and cipher
            encryptGroupCipher = new GroupCipher(senderStore, senderKeyName);

            //Send a message to contacts which is automatically a SenderKeyDistributionMessage message by default as we have no existing session
            //Used by other contacts to initiate read session from you
            SenderKeyDistributionMessage senderDistributionMessage = sessionBuilder.create(senderKeyName);
            for (AxolotlAddress contact : contacts) {
                ServerAPI.sendMessage(this.address.getName(), contact.getName(), senderDistributionMessage.serialize());
            }

        } else {

            System.out.println(this.address.getName() + " - Multiple contact, will wait for group session initiation");
        }

        //Let's poll (pretend this is push notification-triggered) for session initiation from other contacts
        //TODO merge into basic polling to initiate sessions as needed
        do {
            Map<String, List<byte[]>> bundle = ServerAPI.retreiveMessages(this.address.getName());

            for (Map.Entry<String, List<byte[]>> subbundle : bundle.entrySet()) {

                List<byte[]> messages = subbundle.getValue();

                //Group session has not even been started

                //Imagine this message was received wrapped in group information such as member list, group name and such.
                SenderKeyDistributionMessage senderKeyDistributionMessage = new SenderKeyDistributionMessage(messages.get(0));

                // Instantiate a Sender's key representing the group from the sending contact
                AxolotlAddress groupInitiator = contacts.stream().filter(v -> v.getName().equalsIgnoreCase(subbundle.getKey())).findFirst().get();
                SenderKeyName senderKeyName = new SenderKeyName(groupName, groupInitiator);

                //Start the session for reading group originator
                sessionBuilder.process(senderKeyName, senderKeyDistributionMessage);

                //Save the decryption group cipher for that contact
                decryptGroupCiphers.put(subbundle.getKey(), new GroupCipher(senderStore, senderKeyName));

                //Only run this on group initiation
                if (encryptGroupCipher == null) {
                    //Create the encryption group cipher
                    encryptGroupCipher = new GroupCipher(senderStore, new SenderKeyName(groupName, this.address));

                    //Send a message to all other group members (SenderKeyDistributionMessage)
                    //Used by other contacts to initiate read session from you
                    SenderKeyDistributionMessage senderDistributionMessage = sessionBuilder.create(new SenderKeyName(groupName, this.address));
                    for (AxolotlAddress contact : contacts) {
                        ServerAPI.sendMessage(this.address.getName(), contact.getName(), senderDistributionMessage.serialize());
                    }

                    System.out.println(this.address.getName() + " - Started group chat session '" + groupName + "' initiated from " + subbundle.getKey());
                } else {
                    System.out.println(this.address.getName() + " - Received decryption session from " + subbundle.getKey());
                }

                messages.remove(0);

                //If more stacked messages, process to ratchet the cipher (should not happen in this setup)
                for (byte[] message : messages) {
                    byte[] text = encryptGroupCipher.decrypt(message);
                    System.out.println(this.address.getName() + " <- " + subbundle.getKey() + ": " + new String(text, StandardCharsets.UTF_8));
                }
            }

            //Give it a bit of latency between checks
            Thread.sleep(100);

        } while (decryptGroupCiphers.size() < 2);

        //Let's give use some time to setup the group chat since we do actually check the message type and it would be weird to
        Thread.sleep(3000);

        // Let's now play the game of sending random messages,
        // at random times, a random number of times before checking
        // for random amounts of time
        List<byte[]> pendingMessages = new ArrayList<>();
        do {
            boolean active    = random.nextBoolean();
            boolean connected = random.nextBoolean();

            //User is actively sending messages, internet might be bad.
            if (active) {
                //Send a few messages messages
                for (int i = 0; i < random.nextInt(4); i++) {

                    try {
                        String message = faker.lorem().sentence();

                        pendingMessages.add(encryptGroupCipher.encrypt(message.getBytes(StandardCharsets.UTF_8)));

                        System.out.println(this.address.getName() + " -> GROUP: " + message);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    Thread.sleep(random.nextInt(3) * 200);
                }
            }

            //User has internet connectivity, sends and receive pending messaged
            if (connected) {

                //Send
                for (byte[] message : pendingMessages) {

                    //Send copies for each contact
                    for (AxolotlAddress contact : contacts) {
                        ServerAPI.sendMessage(this.address.getName(), contact.getName(), message);
                    }
                }
                pendingMessages.clear();

                //Receive
                Map<String, List<byte[]>> bundle = ServerAPI.retreiveMessages(this.address.getName());
                for (Map.Entry<String, List<byte[]>> subbundle : bundle.entrySet()) {
                    String name = subbundle.getKey();
                    List<byte[]> messages = subbundle.getValue();
                    GroupCipher decryptGroupCiphes = decryptGroupCiphers.get(name);

                    for (byte[] message : messages) {
                        try {
                            byte[] text = decryptGroupCiphes.decrypt(message);
                            System.out.println(this.address.getName() + " <- " + name + ": " + new String(text, StandardCharsets.UTF_8));
                        } catch (Exception e) {
                            System.out.println("ERROR - " + this.address.getName() + " cannot decrypt message from " + name + ". Received " + Arrays.toString(message));
                        }
                    }
                }
            }

            Thread.sleep(random.nextInt(3) * 1000);
        } while (true);
    }

    private byte[] prepareMessage(String to, String message, SessionCipher sessionCipher) {

        System.out.println(this.address.getName() + " -> " + to + ": " + message);

        return sessionCipher.encrypt(message.getBytes(StandardCharsets.UTF_8)).serialize();
    }

}