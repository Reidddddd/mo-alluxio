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

package alluxio.security;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class implements parsing and handling of Kerberos principal names.
 */
public class KerberosUser {
  /** The first component of principal. */
  private final String mServiceName;
  /** The second component of principal, it may be null. */
  private final String mHostName;
  /** The realm of principal. */
  private final String mRealm;

  /** A pattern that matches a Kerberos name with at most 2 components. */
  private static final Pattern PRINCIPAL_PARSER =
      Pattern.compile("([^/@]+)(/([^/@]+))?(@([^/@]+))?");

  /**
   * Construtor of kerberos principal.
   * @param principal principal name
   */
  public KerberosUser(String principal) {
    Matcher matcher = PRINCIPAL_PARSER.matcher(principal);
    if (!matcher.matches()) {
      if (principal.contains("@")) {
        throw new IllegalArgumentException("Malformed Kerberos name: " + principal);
      } else {
        mServiceName = principal;
        mHostName = null;
        mRealm = null;
      }
    } else {
      mServiceName = matcher.group(1);
      mHostName = matcher.group(3);
      mRealm = matcher.group(5);
    }
  }

  /**
   * Get service name in principal.
   * @return service name
   */
  public String getServiceName() {
    return mServiceName;
  }

  /**
   * Get host name in principal.
   * @return host name
   */
  public String getHostName() {
    return mHostName;
  }

  /**
   * Get realm in principal.
   * @return realm
   */
  public String getRealm() {
    return mRealm;
  }

  @Override
  public String toString() {
    StringBuilder principal = new StringBuilder();
    principal.append(mServiceName);
    if (mHostName != null) {
      principal.append('/');
      principal.append(mHostName);
    }
    if (mRealm != null) {
      principal.append('@');
      principal.append(mRealm);
    }
    return principal.toString();
  }
}
