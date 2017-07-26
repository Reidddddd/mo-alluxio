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

package alluxio.security.authentication;

import java.security.Provider;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Kerberos sasl server provider.
 */
@ThreadSafe
public class KerberosSaslServerProvider extends Provider {
  private static final long serialVersionUID = 420587495547165352L;

  public static final String NAME = "Kerberos Provider";
  public static final String MECHANISM = "GSSAPI";
  private static final double VERSION = 1.0;

  /**
   * Server provider for kerberized server.
   */
  protected KerberosSaslServerProvider() {
    super(NAME, VERSION, "Kerberized server provider");
    put("SaslServerFactory." + MECHANISM, KerberosSaslServer.Factory.class.getName());
  }
}
