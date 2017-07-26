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
