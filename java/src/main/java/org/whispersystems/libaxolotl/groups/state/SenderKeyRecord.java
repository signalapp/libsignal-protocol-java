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
package org.whispersystems.libaxolotl.groups.state;

import org.whispersystems.libaxolotl.InvalidKeyIdException;
import org.whispersystems.libaxolotl.ecc.ECKeyPair;
import org.whispersystems.libaxolotl.ecc.ECPublicKey;
import org.whispersystems.libaxolotl.state.StorageProtos;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import static org.whispersystems.libaxolotl.state.StorageProtos.SenderKeyRecordStructure;

/**
 * A durable representation of a set of SenderKeyStates for a specific
 * SenderKeyName.
 *
 * @author Moxie Marlisnpike
 */
public class SenderKeyRecord {

  private static final int MAX_STATES = 5;

  private LinkedList<SenderKeyState> senderKeyStates = new LinkedList<>();

  public SenderKeyRecord() {}

  public SenderKeyRecord(byte[] serialized) throws IOException {
    SenderKeyRecordStructure senderKeyRecordStructure = SenderKeyRecordStructure.parseFrom(serialized);

    for (StorageProtos.SenderKeyStateStructure structure : senderKeyRecordStructure.getSenderKeyStatesList()) {
      this.senderKeyStates.add(new SenderKeyState(structure));
    }
  }

  public boolean isEmpty() {
    return senderKeyStates.isEmpty();
  }

  public SenderKeyState getSenderKeyState() throws InvalidKeyIdException {
    if (!senderKeyStates.isEmpty()) {
      return senderKeyStates.get(0);
    } else {
      throw new InvalidKeyIdException("No key state in record!");
    }
  }

  public SenderKeyState getSenderKeyState(int keyId) throws InvalidKeyIdException {
    for (SenderKeyState state : senderKeyStates) {
      if (state.getKeyId() == keyId) {
        return state;
      }
    }

    throw new InvalidKeyIdException("No keys for: " + keyId);
  }

  public void addSenderKeyState(int id, int iteration, byte[] chainKey, ECPublicKey signatureKey) {
    senderKeyStates.addFirst(new SenderKeyState(id, iteration, chainKey, signatureKey));

    if (senderKeyStates.size() > MAX_STATES) {
      senderKeyStates.removeLast();
    }
  }

  public void setSenderKeyState(int id, int iteration, byte[] chainKey, ECKeyPair signatureKey) {
    senderKeyStates.clear();
    senderKeyStates.add(new SenderKeyState(id, iteration, chainKey, signatureKey));
  }

  public byte[] serialize() {
    SenderKeyRecordStructure.Builder recordStructure = SenderKeyRecordStructure.newBuilder();

    for (SenderKeyState senderKeyState : senderKeyStates) {
      recordStructure.addSenderKeyStates(senderKeyState.getStructure());
    }

    return recordStructure.build().toByteArray();
  }
}
