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

import java.security.Principal;

import javax.annotation.concurrent.ThreadSafe;

/**
 * This class represents a user in Alluxio. It implements {@link java.security.Principal} in the
 * context of Java security frameworks.
 */
@ThreadSafe
public final class User implements Principal {
  private final String mFullName;
  private final String mShortName;

  // TODO(dong): add more attributes and methods for supporting Kerberos

  /**
   * Constructs a new user with a name.
   *
   * @param name the name of the user
   */
  public User(String name) {
    mShortName = new KerberosUserName(name).getShortName();
    mFullName = name;
  }

  @Override
  public String getName() {
    return mFullName;
  }

  /**
   * Short name of user.
   * @return short name
   */
  public String getShortName() {
    return mShortName;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof User)) {
      return false;
    }
    User that = (User) o;
    return mFullName.equals(that.mFullName);
  }

  @Override
  public int hashCode() {
    return mFullName.hashCode();
  }

  @Override
  public String toString() {
    return mFullName;
  }
}
