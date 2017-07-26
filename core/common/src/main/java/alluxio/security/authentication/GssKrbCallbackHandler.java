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
