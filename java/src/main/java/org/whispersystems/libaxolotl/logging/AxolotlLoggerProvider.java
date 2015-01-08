package org.whispersystems.libaxolotl.logging;

public class AxolotlLoggerProvider {

  private static AxolotlLogger provider;

  public static AxolotlLogger getProvider() {
    return provider;
  }

  public static void setProvider(AxolotlLogger provider) {
    AxolotlLoggerProvider.provider = provider;
  }
}
