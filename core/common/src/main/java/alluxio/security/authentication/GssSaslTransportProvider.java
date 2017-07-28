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

import alluxio.Configuration;
import alluxio.PropertyKey;
import alluxio.exception.status.UnauthenticatedException;
import alluxio.security.LoginUser;
import alluxio.security.User;

import org.apache.thrift.transport.TSaslClientTransport;
import org.apache.thrift.transport.TSaslServerTransport;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportFactory;

import java.net.InetSocketAddress;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;

/**
 * Authentication type is {@link AuthType#KERBEROS}.
 */
public class GssSaslTransportProvider implements TransportProvider {

  static {
    Security.addProvider(new KerberosSaslServerProvider());
  }

  /** Timeout for socket in ms. */
  private int mSocketTimeoutMs;

  /**
   * Kerberos transport provider.
   */
  public GssSaslTransportProvider() {
    mSocketTimeoutMs = Configuration.getInt(PropertyKey.SECURITY_AUTHENTICATION_SOCKET_TIMEOUT_MS);
    LoginUser.loginFromKeytab(Configuration.get(PropertyKey.SECURITY_KERBEROS_KEYTAB_FILE),
                              Configuration.get(PropertyKey.SECURITY_KERBEROS_PRINCIPAL));
  }

  @Override
  public TTransport getClientTransport(InetSocketAddress serverAddress)
      throws UnauthenticatedException {
    return getClientTransport(LoginUser.getSubject(), serverAddress);
  }

  @Override
  public TTransport getClientTransport(Subject subject, InetSocketAddress serverAddress)
      throws UnauthenticatedException {
    final TTransport wrappedTransport =
        TransportProviderUtils.createThriftSocket(serverAddress, mSocketTimeoutMs);
    final User user = LoginUser.get();
    final String serverHost = serverAddress.getHostName();
    try {
      return new TSaslClientTransport(KerberosSaslServerProvider.MECHANISM,
                                      user.getName(),
                                      "alluxio",
                                      serverHost,
                                      null,
                                      null,
                                      wrappedTransport);
    } catch (SaslException e) {
      throw new UnauthenticatedException(e);
    }
  }

  @Override
  public TTransportFactory getServerTransportFactory(String serverName) throws SaslException {
    return getServerTransportFactory(null, serverName);
  }

  @Override
  public TTransportFactory getServerTransportFactory(Runnable runnable, String serverName)
      throws SaslException {
    final TSaslServerTransport.Factory saslFactory = new TSaslServerTransport.Factory();
    final String serverHost = serverName;
    final Map<String, String> props = new HashMap<>();
    props.put(Sasl.SERVER_AUTH, "true");
    props.put(Sasl.QOP, "auth");
    return LoginUser.doAs(new PrivilegedAction<TTransportFactory>() {
      @Override
      public TTransportFactory run() {
        saslFactory.addServerDefinition(KerberosSaslServerProvider.MECHANISM,
                                        "alluxio",
                                        serverHost,
                                        props,
                                        new GssKrbCallbackHandler());
        return saslFactory;
      }
    });
  }
}
