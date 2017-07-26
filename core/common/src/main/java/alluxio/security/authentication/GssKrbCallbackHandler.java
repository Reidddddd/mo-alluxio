package alluxio.security.authentication;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

/**
 * Callback handler for SASL GSSAPI Kerberos mechanism.
 */
public class GssKrbCallbackHandler implements CallbackHandler {

  /**
   * Constructor for GssKrbCallbackHandler.
   */
  public GssKrbCallbackHandler() {
  }

  @Override
  public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
    AuthorizeCallback ac = null;
    for (Callback callback :callbacks) {
      if (callback instanceof AuthorizeCallback) {
        ac = (AuthorizeCallback) callback;
      }
    }
    if (ac != null) {
      String authenticationID = ac.getAuthenticationID();
      String authorizationID = ac.getAuthorizationID();
      if (authenticationID.equals(authorizationID)) {
        ac.setAuthorized(true);
      } else {
        ac.setAuthorized(false);
      }
      if (ac.isAuthorized()) {
        ac.setAuthorizedID(authorizationID);
      }
    }
  }
}
