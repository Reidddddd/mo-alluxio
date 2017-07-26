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

package alluxio.util;

import alluxio.Configuration;
import alluxio.PropertyKey;
import alluxio.security.authentication.AuthType;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Utility methods for kerberos.
 */
@ThreadSafe
public final class KerberosUtils {
  /**
   * Prevent initialization.
   */
  private KerberosUtils() {}

  /**
   * If kerberos is enabled.
   * @return true if enabled
   */
  public static boolean isKrbEnable() {
    return Configuration.getEnum(PropertyKey.SECURITY_AUTHENTICATION_TYPE, AuthType.class)
        .equals(AuthType.KERBEROS);
  }

  /**
   * Get kerberos login module based on platform.
   * @return name of module
   */
  public static String getKerberosLoginModuleName() {
    return OSUtils.IBM_JAVA ? "com.ibm.security.auth.module.Krb5LoginModule"
        : "com.sun.security.auth.module.Krb5LoginModule";
  }
}
