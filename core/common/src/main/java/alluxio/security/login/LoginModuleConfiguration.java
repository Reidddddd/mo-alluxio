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

package alluxio.security.login;

import alluxio.PropertyKey;
import alluxio.security.User;
import alluxio.security.authentication.AuthType;
import alluxio.util.KerberosUtils;
import alluxio.util.OSUtils;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.concurrent.ThreadSafe;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;

/**
 * A JAAS configuration that defines the login modules, by which JAAS uses to login.
 *
 * In implementation, we define several modes (Simple, Kerberos, ...) by constructing different
 * arrays of AppConfigurationEntry, and select the proper array based on the configured mode.
 *
 * Then JAAS login framework use the selected array of AppConfigurationEntry to determine the login
 * modules to be used.
 */
@ThreadSafe
public final class LoginModuleConfiguration extends Configuration {

  private static final Map<String, String> EMPTY_JAAS_OPTIONS = new HashMap<>();
  private static final Map<String, String> KEYTAB_KERBEROS_OPTIONS = new HashMap<>();

  static {
    if (OSUtils.IBM_JAVA) {
      KEYTAB_KERBEROS_OPTIONS.put("credsType", "both");
    } else {
      KEYTAB_KERBEROS_OPTIONS.put("doNotPrompt", "true");
      KEYTAB_KERBEROS_OPTIONS.put("useKeyTab", "true");
      KEYTAB_KERBEROS_OPTIONS.put("storeKey", "true");
    }
    KEYTAB_KERBEROS_OPTIONS.put("refreshKrb5Config", "true");
  }

  private static final Map<String, String> USER_KERBEROS_OPTIONS = new HashMap<>();

  static {
    if (OSUtils.IBM_JAVA) {
      USER_KERBEROS_OPTIONS.put("useDefaultCcache", "true");
    } else {
      USER_KERBEROS_OPTIONS.put("doNotPrompt", "true");
      USER_KERBEROS_OPTIONS.put("useTicketCache", "true");
    }
    String ticketCache = System.getenv("KRB5CCNAME");
    if (ticketCache != null) {
      if (OSUtils.IBM_JAVA) {
        // The first value searched when "useDefaultCcache" is used.
        System.setProperty("KRB5CCNAME", ticketCache);
      } else {
        USER_KERBEROS_OPTIONS.put("ticketCache", ticketCache);
      }
    }
    USER_KERBEROS_OPTIONS.put("renewTGT", "true");
  }

  /** Login module that allows a user name provided by OS. */
  private static final AppConfigurationEntry OS_SPECIFIC_LOGIN =
      new AppConfigurationEntry(LoginModuleConfigurationUtils.OS_LOGIN_MODULE_NAME,
          LoginModuleControlFlag.REQUIRED, EMPTY_JAAS_OPTIONS);

  /** Login module that allows a user name provided by application to be specified. */
  private static final AppConfigurationEntry APP_LOGIN = new AppConfigurationEntry(
      AppLoginModule.class.getName(), LoginModuleControlFlag.SUFFICIENT, EMPTY_JAAS_OPTIONS);

  /** Login module that allows a user name provided by an Alluxio specific login module. */
  private static final AppConfigurationEntry ALLUXIO_LOGIN = new AppConfigurationEntry(
      AlluxioLoginModule.class.getName(), LoginModuleControlFlag.REQUIRED, EMPTY_JAAS_OPTIONS);

  /** Kerberos login module for a user. */
  private static final AppConfigurationEntry KERBEROS_LOGIN =
      new AppConfigurationEntry(KerberosUtils.getKerberosLoginModuleName(),
                                LoginModuleControlFlag.OPTIONAL,
                                USER_KERBEROS_OPTIONS);

  /** Kerberos login module for a server(keytab). */
  private static final AppConfigurationEntry KERBEROS_KEYTAB_LOGIN =
      new AppConfigurationEntry(KerberosUtils.getKerberosLoginModuleName(),
                                LoginModuleControlFlag.REQUIRED,
                                KEYTAB_KERBEROS_OPTIONS);
  /**
   * In the {@link AuthType#SIMPLE} mode, JAAS first tries to retrieve the user name set by the
   * application with {@link AppLoginModule}. Upon failure, it uses the OS specific login module to
   * fetch the OS user, and then uses {@link AlluxioLoginModule} to convert it to an Alluxio user
   * represented by {@link User}. In {@link AuthType#CUSTOM} mode, we also use this configuration.
   */
  private static final AppConfigurationEntry[] SIMPLE =
      new AppConfigurationEntry[] {APP_LOGIN, OS_SPECIFIC_LOGIN, ALLUXIO_LOGIN};

  /**
   * {@link AuthType#KERBEROS} mode.
   */
  private static final AppConfigurationEntry[] KERBEROS =
      new AppConfigurationEntry[] { OS_SPECIFIC_LOGIN, KERBEROS_LOGIN, ALLUXIO_LOGIN };

  /**
   * {@link AuthType#KERBEROS_KEYTAB} mode for long running job.
   */
  private static final AppConfigurationEntry[] KERBEROS_KEYTAB =
      new AppConfigurationEntry[] { KERBEROS_KEYTAB_LOGIN, ALLUXIO_LOGIN };

  /**
   * Constructs a new {@link LoginModuleConfiguration}.
   */
  public LoginModuleConfiguration() {}

  @Override
  public AppConfigurationEntry[] getAppConfigurationEntry(String appName) {
    if (appName.equalsIgnoreCase(AuthType.SIMPLE.getAuthName())
        || appName.equalsIgnoreCase(AuthType.CUSTOM.getAuthName())) {
      return SIMPLE;
    } else if (appName.equalsIgnoreCase(AuthType.KERBEROS.getAuthName())) {
      return KERBEROS;
    } else if (appName.equalsIgnoreCase(AuthType.KERBEROS_KEYTAB.getAuthName())) {
      if (OSUtils.IBM_JAVA) {
        KEYTAB_KERBEROS_OPTIONS.put("useKeytab",
            addFilePrefix(alluxio.Configuration.get(PropertyKey.SECURITY_KERBEROS_KEYTAB_FILE)));
      } else {
        KEYTAB_KERBEROS_OPTIONS.put("keyTab",
            alluxio.Configuration.get(PropertyKey.SECURITY_KERBEROS_KEYTAB_FILE));
      }
      KEYTAB_KERBEROS_OPTIONS.put("principal",
          alluxio.Configuration.get(PropertyKey.SECURITY_KERBEROS_PRINCIPAL));
      return KERBEROS_KEYTAB;
    }
    return null;
  }

  private static String addFilePrefix(String keytab) {
    return keytab.startsWith("file://") ? keytab : "file://" + keytab;
  }
}
