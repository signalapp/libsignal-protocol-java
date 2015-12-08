package org.whispersystems.libaxolotl.fingerprint;

public class Fingerprint {

  private final DisplayableFingerprint displayableFingerprint;
  private final ScannableFingerprint   scannableFingerprint;

  public Fingerprint(DisplayableFingerprint displayableFingerprint,
                     ScannableFingerprint scannableFingerprint)
  {
    this.displayableFingerprint = displayableFingerprint;
    this.scannableFingerprint   = scannableFingerprint;
  }

  /**
   * @return A text fingerprint that can be displayed and compared remotely.
   */
  public DisplayableFingerprint getDisplayableFingerprint() {
    return displayableFingerprint;
  }

  /**
   * @return A scannable fingerprint that can be scanned anc compared locally.
   */
  public ScannableFingerprint getScannableFingerprint() {
    return scannableFingerprint;
  }
}
