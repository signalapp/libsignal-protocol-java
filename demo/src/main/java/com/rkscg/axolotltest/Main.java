/**
 * @Author Vincent
 */
package com.rkscg.axolotltest;

import com.github.javafaker.Faker;
import com.rkscg.axolotltest.client.ClientRunnable;
import org.whispersystems.libaxolotl.InvalidKeyException;

import java.io.Console;
import java.lang.reflect.Field;
import java.security.PermissionCollection;
import java.security.Permission;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

public class Main {

    public static void main(String [] args) throws InvalidKeyException, InterruptedException {

        System.out.println("System - Booting up");

        removeCryptographyRestrictions();

        int participants = 2;
        if (args.length > 0 && isInteger(args[0]))
            participants = Math.min(Integer.parseInt(args[0]), 26);

        if (participants == 2)
            startOneOnOneSession();
        else
            startGroupSession(participants);

        System.out.println("System - Execution stopping");
    }

    private static void startOneOnOneSession() throws InvalidKeyException, InterruptedException {

        // Let's boot up 2 clients, Alice and Bob
        ClientRunnable alice = new ClientRunnable("Alice", 5);
        ClientRunnable bob   = new ClientRunnable("Bob",  28);

        Thread aliceThread = new Thread(alice);
        Thread bobThread   = new Thread(bob);

        aliceThread.start();
        bobThread.start();

        while (aliceThread.isAlive() && bobThread.isAlive()) {

            Thread.sleep(1000);
        }
    }

    private static void startGroupSession(int participants) throws InvalidKeyException, InterruptedException {

        Faker faker = new Faker();
        Random random = new Random();

        // Let's boot up 2 clients, Alice and Bob
        ClientRunnable alice   = new ClientRunnable("Alice",   1);
        Thread aliceThread   = new Thread(alice);

        ClientRunnable bob     = new ClientRunnable("Bob",     2);
        Thread bobThread     = new Thread(bob);

        ClientRunnable charlie = new ClientRunnable("Charlie", 3);
        Thread charlieThread = new Thread(charlie);

        List<Thread> threads = new ArrayList<>();
        for (int i = 3; i < participants; i++) {
            //Alphabetical name hahaha
            String name = String.valueOf((char)(i + 65)) + faker.name().firstName().substring(1);
            threads.add(new Thread(new ClientRunnable(name, i)));
        }

        aliceThread.start();
        bobThread.start();
        charlieThread.start();

        for (Thread client : threads) {
            client.start();
        }

        boolean keepRunning = true;
        do {
            Thread.sleep(1000);

            if (!aliceThread.isAlive() || !bobThread.isAlive() || !charlieThread.isAlive())
                keepRunning = false;

            for (Thread client : threads) {
                if (!client.isAlive())
                    keepRunning = false;
            }

        } while (keepRunning);
    }

    private static void removeCryptographyRestrictions() {
        if (!isRestrictedCryptography()) {
            System.out.println("Cryptography restrictions removal not needed");
            return;
        }
        try {
        /*
         * Do the following, but with reflection to bypass access checks:
         *
         * JceSecurity.isRestricted = false;
         * JceSecurity.defaultPolicy.perms.clear();
         * JceSecurity.defaultPolicy.add(CryptoAllPermission.INSTANCE);
         */
            final Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
            final Class<?> cryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
            final Class<?> cryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");

            final Field isRestrictedField = jceSecurity.getDeclaredField("isRestricted");
            isRestrictedField.setAccessible(true);
            isRestrictedField.set(null, false);

            final Field defaultPolicyField = jceSecurity.getDeclaredField("defaultPolicy");
            defaultPolicyField.setAccessible(true);
            final PermissionCollection defaultPolicy = (PermissionCollection) defaultPolicyField.get(null);

            final Field perms = cryptoPermissions.getDeclaredField("perms");
            perms.setAccessible(true);
            ((Map<?, ?>) perms.get(defaultPolicy)).clear();

            final Field instance = cryptoAllPermission.getDeclaredField("INSTANCE");
            instance.setAccessible(true);
            defaultPolicy.add((Permission) instance.get(null));

            System.out.println("Successfully removed cryptography restrictions");
        } catch (final Exception e) {
            System.out.println("Failed to remove cryptography restrictions");
        }
    }

    private static boolean isRestrictedCryptography() {
        // This simply matches the Oracle JRE, but not OpenJDK.
        return "Java(TM) SE Runtime Environment".equals(System.getProperty("java.runtime.name"));
    }

    public static boolean isInteger(String s) {
        if(s.isEmpty()) return false;
        for(int i = 0; i < s.length(); i++) {
            if(i == 0 && s.charAt(i) == '-') {
                if(s.length() == 1) return false;
                else continue;
            }
            if(Character.digit(s.charAt(i), 10) < 0) return false;
        }
        return true;
    }
}
