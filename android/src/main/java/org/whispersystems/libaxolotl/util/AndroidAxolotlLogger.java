package org.whispersystems.libaxolotl.util;

import android.util.Log;
import android.util.SparseIntArray;

import org.whispersystems.libaxolotl.logging.AxolotlLogger;

public class AndroidAxolotlLogger implements AxolotlLogger {

  private static final SparseIntArray PRIORITY_MAP = new SparseIntArray(5) {{
    put(AxolotlLogger.INFO, Log.INFO);
    put(AxolotlLogger.ASSERT, Log.ASSERT);
    put(AxolotlLogger.DEBUG, Log.DEBUG);
    put(AxolotlLogger.VERBOSE, Log.VERBOSE);
    put(AxolotlLogger.WARN, Log.WARN);

  }};

  @Override
  public void log(int priority, String tag, String message) {
    int androidPriority = PRIORITY_MAP.get(priority, Log.WARN);
    Log.println(androidPriority, tag, message);
  }
}
