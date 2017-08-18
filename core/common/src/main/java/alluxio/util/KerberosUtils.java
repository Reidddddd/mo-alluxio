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

import java.lang.reflect.Method;

import javax.annotation.concurrent.ThreadSafe;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;

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
   * Get default realm.
   * @return name of realm
   */
  public static String getDefaultRealm() {
    Object kerbConf;
    Class<?> classRef;
    Method getInstanceMethod;
    Method getDefaultRealmMethod;
    try {
      if (OSUtils.IBM_JAVA) {
        classRef = Class.forName("com.ibm.security.krb5.internal.Config");
      } else {
        classRef = Class.forName("sun.security.krb5.Config");
      }
      getInstanceMethod = classRef.getMethod("getInstance", new Class[0]);
      kerbConf = getInstanceMethod.invoke(classRef, new Object[0]);
      getDefaultRealmMethod = classRef.getDeclaredMethod("getDefaultRealm", new Class[0]);
      return (String) getDefaultRealmMethod.invoke(kerbConf, new Object[0]);
    } catch (Exception e) {
      // return "" in this case.
    }
    return "";
  }

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

  /**
   * Check whether the server principal is the TGS's principal.
   * @param ticket the original TGT
   * @return true or false
   */
  public static boolean isOriginalTGT(KerberosTicket ticket) {
    return isTGTPrincipal(ticket.getServer());
  }

  private static boolean isTGTPrincipal(KerberosPrincipal principal) {
    if (principal == null) {
      return false;
    }
    if (principal.getName().equals("krbtgt/" + principal.getRealm() + "@" + principal.getRealm())) {
      return true;
    }
    return false;
  }
}
