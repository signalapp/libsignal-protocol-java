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

/**
 * A representation of a (groupId + senderId + deviceId) tuple.
 */
public class SenderKeyName {

  private final String groupId;
  private final long   senderId;
  private final int    deviceId;

  public SenderKeyName(String groupId, long senderId, int deviceId) {
    this.groupId  = groupId;
    this.senderId = senderId;
    this.deviceId = deviceId;
  }

  public String getGroupId() {
    return groupId;
  }

  public long getSenderId() {
    return senderId;
  }

  public int getDeviceId() {
    return deviceId;
  }

  public String serialize() {
    return groupId + "::" + String.valueOf(senderId) + "::" + String.valueOf(deviceId);
  }

  @Override
  public boolean equals(Object other) {
    if (other == null)                     return false;
    if (!(other instanceof SenderKeyName)) return false;

    SenderKeyName that = (SenderKeyName)other;

    return
        this.groupId.equals(that.groupId) &&
        this.senderId == that.senderId &&
        this.deviceId == that.deviceId;
  }

  @Override
  public int hashCode() {
    return this.groupId.hashCode() ^ (int)this.senderId ^ this.deviceId;
  }

}
