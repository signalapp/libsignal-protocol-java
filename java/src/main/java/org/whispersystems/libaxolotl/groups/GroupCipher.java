/**
 * Copyright (C) 2014-2015 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.whispersystems.libaxolotl.groups;

import org.whispersystems.libaxolotl.DecryptionCallback;
import org.whispersystems.libaxolotl.DuplicateMessageException;
import org.whispersystems.libaxolotl.InvalidKeyIdException;
import org.whispersystems.libaxolotl.InvalidMessageException;
import org.whispersystems.libaxolotl.LegacyMessageException;
import org.whispersystems.libaxolotl.NoSessionException;
import org.whispersystems.libaxolotl.groups.ratchet.SenderChainKey;
import org.whispersystems.libaxolotl.groups.ratchet.SenderMessageKey;
import org.whispersystems.libaxolotl.groups.state.SenderKeyRecord;
import org.whispersystems.libaxolotl.groups.state.SenderKeyState;
import org.whispersystems.libaxolotl.groups.state.SenderKeyStore;
import org.whispersystems.libaxolotl.protocol.SenderKeyMessage;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The main entry point for axolotl group encrypt/decrypt operations.
 *
 * Once a session has been established with {@link org.whispersystems.libaxolotl.groups.GroupSessionBuilder}
 * and a {@link org.whispersystems.libaxolotl.protocol.SenderKeyDistributionMessage} has been
 * distributed to each member of the group, this class can be used for all subsequent encrypt/decrypt
 * operations within that session (ie: until group membership changes).
 *
 * @author Moxie Marlinspike
 */
public class GroupCipher {

  static final Object LOCK = new Object();

  private final SenderKeyStore senderKeyStore;
  private final SenderKeyName senderKeyId;

  public GroupCipher(SenderKeyStore senderKeyStore, SenderKeyName senderKeyId) {
    this.senderKeyStore = senderKeyStore;
    this.senderKeyId    = senderKeyId;
  }

  /**
   * Encrypt a message.
   *
   * @param paddedPlaintext The plaintext message bytes, optionally padded.
   * @return Ciphertext.
   * @throws NoSessionException
   */
  public byte[] encrypt(byte[] paddedPlaintext) throws NoSessionException {
    synchronized (LOCK) {
      try {
        SenderKeyRecord  record         = senderKeyStore.loadSenderKey(senderKeyId);
        SenderKeyState   senderKeyState = record.getSenderKeyState();
        SenderMessageKey senderKey      = senderKeyState.getSenderChainKey().getSenderMessageKey();
        byte[]           ciphertext     = getCipherText(senderKey.getIv(), senderKey.getCipherKey(), paddedPlaintext);

        SenderKeyMessage senderKeyMessage = new SenderKeyMessage(senderKeyState.getKeyId(),
                                                                 senderKey.getIteration(),
                                                                 ciphertext,
                                                                 senderKeyState.getSigningKeyPrivate());

        senderKeyState.setSenderChainKey(senderKeyState.getSenderChainKey().getNext());

        senderKeyStore.storeSenderKey(senderKeyId, record);

        return senderKeyMessage.serialize();
      } catch (InvalidKeyIdException e) {
        throw new NoSessionException(e);
      }
    }
  }

  /**
   * Decrypt a SenderKey group message.
   *
   * @param senderKeyMessageBytes The received ciphertext.
   * @return Plaintext
   * @throws LegacyMessageException
   * @throws InvalidMessageException
   * @throws DuplicateMessageException
   */
  public byte[] decrypt(byte[] senderKeyMessageBytes)
      throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException
  {
    return decrypt(senderKeyMessageBytes, new NullDecryptionCallback());
  }

  /**
   * Decrypt a SenderKey group message.
   *
   * @param senderKeyMessageBytes The received ciphertext.
   * @param callback   A callback that is triggered after decryption is complete,
   *                    but before the updated session state has been committed to the session
   *                    DB.  This allows some implementations to store the committed plaintext
   *                    to a DB first, in case they are concerned with a crash happening between
   *                    the time the session state is updated but before they're able to store
   *                    the plaintext to disk.
   * @return Plaintext
   * @throws LegacyMessageException
   * @throws InvalidMessageException
   * @throws DuplicateMessageException
   */
  public byte[] decrypt(byte[] senderKeyMessageBytes, DecryptionCallback callback)
      throws LegacyMessageException, InvalidMessageException, DuplicateMessageException,
             NoSessionException
  {
    synchronized (LOCK) {
      try {
        SenderKeyRecord record = senderKeyStore.loadSenderKey(senderKeyId);

        if (record.isEmpty()) {
          throw new NoSessionException("No sender key for: " + senderKeyId);
        }

        SenderKeyMessage senderKeyMessage = new SenderKeyMessage(senderKeyMessageBytes);
        SenderKeyState   senderKeyState   = record.getSenderKeyState(senderKeyMessage.getKeyId());

        senderKeyMessage.verifySignature(senderKeyState.getSigningKeyPublic());

        SenderMessageKey senderKey = getSenderKey(senderKeyState, senderKeyMessage.getIteration());

        byte[] plaintext = getPlainText(senderKey.getIv(), senderKey.getCipherKey(), senderKeyMessage.getCipherText());

        callback.handlePlaintext(plaintext);

        senderKeyStore.storeSenderKey(senderKeyId, record);

        return plaintext;
      } catch (org.whispersystems.libaxolotl.InvalidKeyException | InvalidKeyIdException e) {
        throw new InvalidMessageException(e);
      }
    }
  }

  private SenderMessageKey getSenderKey(SenderKeyState senderKeyState, int iteration)
      throws DuplicateMessageException, InvalidMessageException
  {
    SenderChainKey senderChainKey = senderKeyState.getSenderChainKey();

    if (senderChainKey.getIteration() > iteration) {
      if (senderKeyState.hasSenderMessageKey(iteration)) {
        return senderKeyState.removeSenderMessageKey(iteration);
      } else {
        throw new DuplicateMessageException("Received message with old counter: " +
                                            senderChainKey.getIteration() + " , " + iteration);
      }
    }

    if (senderChainKey.getIteration() - iteration > 2000) {
      throw new InvalidMessageException("Over 2000 messages into the future!");
    }

    while (senderChainKey.getIteration() < iteration) {
      senderKeyState.addSenderMessageKey(senderChainKey.getSenderMessageKey());
      senderChainKey = senderChainKey.getNext();
    }

    senderKeyState.setSenderChainKey(senderChainKey.getNext());
    return senderChainKey.getSenderMessageKey();
  }

  private byte[] getPlainText(byte[] iv, byte[] key, byte[] ciphertext)
      throws InvalidMessageException
  {
    try {
      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
      Cipher          cipher          = Cipher.getInstance("AES/CBC/PKCS5Padding");

      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), ivParameterSpec);

      return cipher.doFinal(ciphertext);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | java.security.InvalidKeyException |
             InvalidAlgorithmParameterException e)
    {
      throw new AssertionError(e);
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new InvalidMessageException(e);
    }
  }

  private byte[] getCipherText(byte[] iv, byte[] key, byte[] plaintext) {
    try {
      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
      Cipher          cipher          = Cipher.getInstance("AES/CBC/PKCS5Padding");

      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), ivParameterSpec);

      return cipher.doFinal(plaintext);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
             IllegalBlockSizeException | BadPaddingException | java.security.InvalidKeyException e)
    {
      throw new AssertionError(e);
    }
  }

  private static class NullDecryptionCallback implements DecryptionCallback {
    @Override
    public void handlePlaintext(byte[] plaintext) {}
  }

}
