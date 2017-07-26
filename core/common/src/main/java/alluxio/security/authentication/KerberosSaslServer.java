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

import com.google.common.base.Preconditions;

import java.util.Map;

import javax.annotation.concurrent.ThreadSafe;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

/**
 * Kerberos sasl server.
 */
@ThreadSafe
public final class KerberosSaslServer {
  /**
   * Constructor for kerberos sasl server.
   */
  private KerberosSaslServer() {
  }

  /**
   * This class is used to create an instances of {@link KerberosSaslServer}.
   * The parameter mechanism must be "GSSAPI" when this Factory is called,
   * or null will be returned.
   */
  @ThreadSafe
  public static class Factory implements SaslServerFactory {

    /**
     * Constructs a new {@link Factory} for the {@link KerberosSaslServer}.
     */
    public Factory() {}

    @Override
    public SaslServer createSaslServer(String mechanism, String protocol, String serverName,
        Map<String, ?> props, CallbackHandler cbh) throws SaslException {
      Preconditions.checkArgument(mechanism.equals(KerberosSaslServerProvider.MECHANISM));
      return Sasl.createSaslServer(mechanism,
                                   protocol,
                                   serverName,
                                   props,
                                   new GssKrbCallbackHandler());
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
      return new String[] { KerberosSaslServerProvider.MECHANISM };
    }
  }
}
