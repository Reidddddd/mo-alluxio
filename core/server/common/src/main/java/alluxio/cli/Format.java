/*
 * The Alluxio Open Foundation licenses this work under the Apache License, version 2.0
 * (the "License"). You may not use this work except in compliance with the License, which is
 * available at www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied, as more fully set forth in the License.
 *
 * See the NOTICE file distributed with this work for information regarding copyright ownership.
 */

package alluxio.cli;

import alluxio.Configuration;
import alluxio.PropertyKey;
import alluxio.RuntimeConstants;
import alluxio.ServiceUtils;
import alluxio.master.journal.Journal;
import alluxio.security.LoginUser;
import alluxio.util.KerberosUtils;
import alluxio.util.io.FileUtils;
import alluxio.util.io.PathUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Formats the Alluxio file system.
 */
@ThreadSafe
public final class Format {
  private static final Logger LOG = LoggerFactory.getLogger(Format.class);
  private static final String USAGE = String.format("java -cp %s %s <MASTER/WORKER>",
      RuntimeConstants.ALLUXIO_JAR, Format.class.getCanonicalName());

  /**
   * The format mode.
   */
  public enum Mode {
    MASTER,
    WORKER,
  }

  /**
   * Formats the worker data folder.
   *
   * @param folder folder path
   */
  private static void formatWorkerDataFolder(String folder) throws IOException {
    Path path = Paths.get(folder);
    if (Files.exists(path)) {
      FileUtils.deletePathRecursively(folder);
    }
    Files.createDirectory(path);
    // For short-circuit read/write to work, others needs to be able to access this directory.
    // This may not be granted when umask bit of others is set to 7 in the system.
    Set<PosixFilePermission> perm = Files.getPosixFilePermissions(path);
    if (!perm.contains(PosixFilePermission.OTHERS_EXECUTE)) {
      perm.add(PosixFilePermission.OTHERS_EXECUTE);
      Files.setPosixFilePermissions(path, perm);
    }
  }

  /**
   * Formats the Alluxio file system.
   *
   * @param args either {@code MASTER} or {@code WORKER}
   */
  public static void main(String[] args) {
    if (args.length != 1) {
      LOG.info(USAGE);
      System.exit(-1);
    }
    Mode mode = null;
    try {
      mode = Mode.valueOf(args[0].toUpperCase());
    } catch (IllegalArgumentException e) {
      LOG.error("Unrecognized format mode: {}", args[0]);
      LOG.error("Usage: {}", USAGE);
      System.exit(-1);
    }
    try {
      format(mode);
    } catch (Exception e) {
      LOG.error("Failed to format", e);
      System.exit(-1);
    }
    LOG.info("Formatting complete");
    System.exit(0);
  }

  /**
   * Formats the Alluxio file system.
   *
   * @param mode either {@code MASTER} or {@code WORKER}
   */
  public static void format(Mode mode) throws IOException {
    switch (mode) {
      case MASTER:
        String masterJournal = Configuration.get(PropertyKey.MASTER_JOURNAL_FOLDER);
        if (KerberosUtils.isKrbEnable()) {
          LoginUser.loginFromKeytab(Configuration.get(PropertyKey.MASTER_KEYTAB_KEY_FILE),
                                    Configuration.get(PropertyKey.MASTER_PRINCIPAL));
        }
        LOG.info("MASTER JOURNAL: {}", masterJournal);
        Journal.Factory factory;
        try {
          factory = new Journal.Factory(new URI(masterJournal));
        } catch (URISyntaxException e) {
          throw new IOException(e.getMessage());
        }
        for (String masterServiceName : ServiceUtils.getMasterServiceNames()) {
          factory.create(masterServiceName).format();
        }
        break;
      case WORKER:
        String workerDataFolder = Configuration.get(PropertyKey.WORKER_DATA_FOLDER);
        LOG.info("Formatting worker data folder: {}", workerDataFolder);
        if (KerberosUtils.isKrbEnable()) {
          LoginUser.loginFromKeytab(Configuration.get(PropertyKey.WORKER_KEYTAB_FILE),
                                    Configuration.get(PropertyKey.WORKER_PRINCIPAL));
        }
        int storageLevels = Configuration.getInt(PropertyKey.WORKER_TIERED_STORE_LEVELS);
        for (int level = 0; level < storageLevels; level++) {
          PropertyKey tierLevelDirPath =
              PropertyKey.Template.WORKER_TIERED_STORE_LEVEL_DIRS_PATH.format(level);
          String[] dirPaths = Configuration.get(tierLevelDirPath).split(",");
          String name = "Data path for tier " + level;
          for (String dirPath : dirPaths) {
            String dirWorkerDataFolder = PathUtils.getWorkerDataDirectory(dirPath);
            LOG.info("Formatting {}:{}", name, dirWorkerDataFolder);
            formatWorkerDataFolder(dirWorkerDataFolder);
          }
        }
        break;
      default:
        throw new RuntimeException(String.format("Unrecognized format mode: %s", mode));
    }
  }

  private Format() {} // prevent instantiation
}
