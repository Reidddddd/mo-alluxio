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

import alluxio.Configuration;
import alluxio.PropertyKey;
import alluxio.exception.status.UnauthenticatedException;
import alluxio.security.authentication.AuthType;
import alluxio.security.login.AlluxioLoginModule;
import alluxio.security.login.AppLoginModule;
import alluxio.security.login.LoginModuleConfiguration;
import alluxio.util.KerberosUtils;

import org.apache.thrift.transport.TTransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Set;

import javax.annotation.concurrent.ThreadSafe;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * A Singleton of LoginUser, which is an instance of {@link alluxio.security.User}. It represents
 * the user of Alluxio client, when connecting to Alluxio service.
 *
 * The implementation of getting a login user supports Windows, Unix, and Kerberos login modules.
 *
 * This singleton uses lazy initialization.
 */
@ThreadSafe
public final class LoginUser {
  private static final Logger LOG = LoggerFactory.getLogger(LoginUser.class);

  /** User instance of the login user in Alluxio client process. */
  private static User sLoginUser;

  /** User entity. */
  private static Subject sSubject;

  private LoginUser() {} // prevent instantiation

  /**
   * Set user's subject.
   * @param subject user's subject
   */
  public static void setUserSubject(Subject subject) {
    sSubject = subject;
    sLoginUser = subject.getPrincipals(User.class).iterator().next();
  }

  /**
   * Get user's subject.
   * @return subject
   */
  public static Subject getSubject() {
    return sSubject;
  }

  /**
   * Gets current singleton login user. This method is called to identify the singleton user who
   * runs Alluxio client. When Alluxio client gets a user by this method and connects to Alluxio
   * service, this user represents the client and is maintained in service.
   *
   * @return the login user
   */
  public static User get() throws UnauthenticatedException {
    if (sLoginUser == null) {
      synchronized (LoginUser.class) {
        if (sLoginUser == null) {
          sLoginUser = login();
        }
      }
    }
    return sLoginUser;
  }

  /**
   * Logs in based on the LoginModules.
   *
   * @return the login user
   */
  private static User login() throws UnauthenticatedException {
    AuthType authType =
        Configuration.getEnum(PropertyKey.SECURITY_AUTHENTICATION_TYPE, AuthType.class);
    checkSecurityEnabled(authType);
    Subject subject = new Subject();

    try {
      // Use the class loader of User.class to construct the LoginContext. LoginContext uses this
      // class loader to dynamically instantiate login modules. This enables
      // Subject#getPrincipals to use reflection to search for User.class instances.
      LoginContext loginContext = createLoginContext(authType, subject, User.class.getClassLoader(),
          new LoginModuleConfiguration());
      loginContext.login();
    } catch (LoginException e) {
      throw new UnauthenticatedException("Failed to login: " + e.getMessage(), e);
    }

    Set<User> userSet = subject.getPrincipals(User.class);
    if (userSet.isEmpty()) {
      throw new UnauthenticatedException("Failed to login: No Alluxio User is found.");
    }
    if (userSet.size() > 1) {
      StringBuilder msg = new StringBuilder(
          "Failed to login: More than one Alluxio Users are found:");
      for (User user : userSet) {
        msg.append(" ").append(user.toString());
      }
      throw new UnauthenticatedException(msg.toString());
    }
    return userSet.iterator().next();
  }

  /**
   * Login as a principal specified in config.
   * @param keytab keytab file location
   * @param principal principal
   */
  public static void loginFromKeytab(final String keytab, final String principal) {
    if (!KerberosUtils.isKrbEnable()) {
      return;
    }
    if (keytab == null || keytab.length() == 0) {
      throw new RuntimeException("Running in secure mode, but config doesn't have a keytab");
    }

    Subject subject = new Subject();
    LoginContext login;
    try {
      login = createLoginContext(AuthType.KERBEROS_KEYTAB,
                                 subject,
                                 AlluxioLoginModule.class.getClassLoader(),
                                 new LoginModuleConfiguration());
      login.login();
    } catch (LoginException e) {
      throw new RuntimeException(String.format("Login failed for user: %s, cause: %s, msg: %s",
        principal, e.getCause(), e.getMessage()));
    }
    checkLogin(subject);
    setUserSubject(subject);
    LOG.info("Login successfully for user {} using keytab file {}.", principal, keytab);
  }

  /**
   * Run the given action as the user.
   * @param <T> the return type of the run method
   * @param action the method to execute
   * @return the value from the run method
   */
  public static <T> T doAs(PrivilegedAction<T> action) {
    return Subject.doAs(sSubject, action);
  }

  /**
   * Run the given action as the user.
   * @param <T> the return type of the run method
   * @param action the method to execute
   * @return the value from the run method
   * @throws IOException
   * @throws TTransportException
   * @throws InterruptedException
   */
  public static <T> T doAs(PrivilegedExceptionAction<T> action)
      throws IOException, TTransportException {
    try {
      return Subject.doAs(sSubject, action);
    } catch (PrivilegedActionException pae) {
      Throwable cause = pae.getCause();
      if (cause == null) {
        throw new RuntimeException("PrivilegedActionException with no underlying cause. User ["
            + sLoginUser + "]" + ": " + pae, pae);
      } else if (cause instanceof IOException) {
        throw (IOException) cause;
      } else if (cause instanceof TTransportException) {
        throw (TTransportException) cause;
      } else if (cause instanceof Error) {
        throw (Error) cause;
      } else if (cause instanceof RuntimeException) {
        throw (RuntimeException) cause;
      } else {
        throw new UndeclaredThrowableException(cause);
      }
    }
  }

  /**
   * Login using ticket cache, mainly from client side.
   */
  public static void loginFromTicketCache() {
    if (!KerberosUtils.isKrbEnable()) {
      return;
    }

    Subject subject = new Subject();
    LoginContext login;
    try {
      login = createLoginContext(AuthType.KERBEROS,
                                 subject,
                                 AlluxioLoginModule.class.getClassLoader(),
                                 new LoginModuleConfiguration());
      login.login();
    } catch (LoginException e) {
      throw new RuntimeException(
        String.format("Login failed using ticket cache, cause: %s, msg: %s",
          e.getCause(), e.getMessage()));
    }

    checkLogin(subject);
    setUserSubject(subject);
  }

  private static void checkLogin(Subject subject) {
    Set<Principal> princs = subject.getPrincipals();
    if (princs.isEmpty()) {
      throw new RuntimeException("No login principals found!");
    }
    if (princs.size() != 1) {
      LOG.warn("Found more than one principal.");
    }
  }

  /**
   * Checks whether Alluxio is running in secure mode, such as {@link AuthType#SIMPLE},
   * {@link AuthType#KERBEROS}, {@link AuthType#CUSTOM}.
   *
   * @param authType the authentication type in configuration
   */
  private static void checkSecurityEnabled(AuthType authType) {
    if (authType != AuthType.SIMPLE
        && authType != AuthType.CUSTOM
        && authType != AuthType.KERBEROS) {
      throw new UnsupportedOperationException("User is not supported in " + authType.getAuthName()
          + " mode");
    }
  }

  /**
   * Creates a new {@link LoginContext} with the correct class loader.
   *
   * @param authType the {@link AuthType} to use
   * @param subject the {@link Subject} to use
   * @param classLoader the {@link ClassLoader} to use
   * @param configuration the {@link javax.security.auth.login.Configuration} to use
   * @return the new {@link LoginContext} instance
   * @throws LoginException if LoginContext cannot be created
   */
  private static LoginContext createLoginContext(AuthType authType, Subject subject,
      ClassLoader classLoader, javax.security.auth.login.Configuration configuration)
      throws LoginException {
    CallbackHandler callbackHandler = null;
    if (authType.equals(AuthType.SIMPLE) || authType.equals(AuthType.CUSTOM)) {
      callbackHandler = new AppLoginModule.AppCallbackHandler();
    }

    ClassLoader previousClassLoader = Thread.currentThread().getContextClassLoader();
    Thread.currentThread().setContextClassLoader(classLoader);
    try {
      // Create LoginContext based on authType, corresponding LoginModule should be registered
      // under the authType name in LoginModuleConfiguration.
      return new LoginContext(authType.getAuthName(), subject, callbackHandler, configuration);
    } finally {
      Thread.currentThread().setContextClassLoader(previousClassLoader);
    }
  }
}
