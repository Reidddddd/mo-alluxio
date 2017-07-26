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
