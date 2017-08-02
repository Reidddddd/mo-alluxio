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

import alluxio.util.KerberosUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class implements parsing and handling of Kerberos principal names.
 */
public class KerberosUserName {
  /** The first component of principal. */
  private final String mServiceName;
  /** The second component of principal, it may be null. */
  private final String mHostName;
  /** The realm of principal. */
  private final String mRealm;

  /** Default realm read from krb5.conf. */
  private static final String DEFAULT_REALM = KerberosUtils.getDefaultRealm();
  /** Rules to parse kerberos principal to specified name. */
  private static List<AuthToLocalRule> sRULES;

  /** A pattern that matches a Kerberos name with at most 2 components. */
  private static final Pattern PRINCIPAL_PARSER =
      Pattern.compile("([^/@]+)(/([^/@]+))?(@([^/@]+))?");
  /** A pattern that matches the format rules. */
  private static final Pattern FORMAT_PARSER = Pattern.compile("([^$]*)(\\$(\\d*))?");
  /** A pattern for parsing a auth_to_local rule. */
  private static final Pattern RULE_PARSER =
      Pattern.compile("\\s*((DEFAULT)|(RULE:\\[(\\d*):([^\\]]*)](\\(([^)]*)\\))?"
                    + "(s/([^/]*)/([^/]*)/(g)?)?))/?(L)?");

  /**
   * Construtor of kerberos principal.
   * @param principal principal name
   */
  public KerberosUserName(String principal) {
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

  /**
   * Get short name of principal after applying auth_to_local rules.
   * @return short name of principal
   */
  public String getShortName() {
    String[] components;
    if (getHostName() == null) {
      if (getRealm() == null) {
        return getServiceName();
      }
      components = new String[] { getRealm(), getServiceName() };
    } else {
      components = new String[] { getRealm(), getServiceName(), getHostName() };
    }
    for (AuthToLocalRule rule : sRULES) {
      String shortName = rule.apply(components);
      if (shortName != null) {
        return shortName;
      }
    }
    // Means no rules applied to the principal name.
    return toString();
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

  private static String authToLocalRule(String base, Pattern origin, String target,
      boolean repeat) {
    Matcher matcher = origin.matcher(base);
    if (repeat) {
      return matcher.replaceAll(target);
    }
    return matcher.replaceFirst(target);
  }

  private static String replaceFormatWithComponents(String format, String[] components) {
    Matcher matcher = FORMAT_PARSER.matcher(format);
    int start = 0;
    StringBuilder res = new StringBuilder();
    while (start < format.length() && matcher.find(start)) {
      res.append(matcher.group(1));
      String paramNum = matcher.group(3);
      if (paramNum != null) {
        int num = Integer.parseInt(paramNum);
        res.append(components[num]);
      }
      start = matcher.end();
    }
    return res.toString();
  }

  private static final class AuthToLocalRule {
    private boolean mIsDefaultRule;
    private int mNumOfComponents;
    private String mFormat;
    private Pattern mMatch;
    private Pattern mOrigin;
    private String mTarget;
    private boolean mRepeat;
    private boolean mToLowerCase;

    static AuthToLocalRule defaults() {
      return new AuthToLocalRule();
    }

    private AuthToLocalRule() {
      mIsDefaultRule = true;
      mNumOfComponents = 0;
      mFormat = null;
      mMatch = null;
      mOrigin = null;
      mTarget = null;
      mRepeat = false;
      mToLowerCase = false;
    }

    AuthToLocalRule setNumOfComponents(int numOfComponents) {
      mNumOfComponents = numOfComponents;
      return this;
    }

    AuthToLocalRule setFormat(String format) {
      mFormat = format;
      return this;
    }

    AuthToLocalRule setMatch(String match) {
      mMatch = match == null ? null : Pattern.compile(match);
      return this;
    }

    AuthToLocalRule setOrigin(String origin) {
      mOrigin = origin == null ? null : Pattern.compile(origin);
      return this;
    }

    AuthToLocalRule setTarget(String target) {
      mTarget = target;
      return this;
    }

    AuthToLocalRule setRepeat(boolean repeat) {
      mRepeat = repeat;
      return this;
    }

    AuthToLocalRule setToLowerCase(boolean toLowerCase) {
      mToLowerCase = toLowerCase;
      return this;
    }

    String apply(String[] components) {
      String shortName = null;
      if (mIsDefaultRule) {
        if (DEFAULT_REALM.equals(components[0])) {
          shortName = components[1];
        }
      } else if (components.length - 1 == mNumOfComponents) {
        String base = replaceFormatWithComponents(mFormat, components);
        if (mMatch == null || mMatch.matcher(base).matches()) {
          if (mOrigin == null) {
            shortName = base;
          } else {
            shortName = authToLocalRule(base, mOrigin, mTarget, mRepeat);
          }
        }
      }
      if (mToLowerCase && shortName != null) {
        shortName = shortName.toLowerCase(Locale.ENGLISH);
      }
      return shortName;
    }

    @Override
    public String toString() {
      StringBuilder buf = new StringBuilder();
      if (mIsDefaultRule) {
        buf.append("DEFAULT");
      } else {
        buf.append("RULE:[");
        buf.append(mNumOfComponents);
        buf.append(':');
        buf.append(mFormat);
        buf.append(']');
        if (mMatch != null) {
          buf.append('(');
          buf.append(mMatch);
          buf.append(')');
        }
        if (mOrigin != null) {
          buf.append("s/");
          buf.append(mOrigin);
          buf.append('/');
          buf.append(mTarget);
          buf.append('/');
          if (mRepeat) {
            buf.append('g');
          }
        }
        if (mToLowerCase) {
          buf.append("/L");
        }
      }
      return buf.toString();
    }
  }

  /**
   * Parse kerberos principal to specified name.
   * @param rules rules read from configuration
   */
  public static void setRules(String rules) {
    sRULES = rules != null ? parseRules(rules) : null;
  }

  private static List<AuthToLocalRule> parseRules(String authToLocalsRules) {
    List<AuthToLocalRule> rules = new ArrayList<>();
    String rule = authToLocalsRules.trim();
    while (rule.length() > 0) {
      Matcher matcher = RULE_PARSER.matcher(rule);
      if (matcher.group(2) != null) {
        // Default rule
        rules.add(AuthToLocalRule.defaults());
      } else {
        rules.add(AuthToLocalRule.defaults()
                                 .setNumOfComponents(Integer.parseInt(matcher.group(4)))
                                 .setFormat(matcher.group(5))
                                 .setMatch(matcher.group(7))
                                 .setOrigin(matcher.group(9))
                                 .setTarget(matcher.group(10))
                                 .setRepeat("g".equals(matcher.group(11)))
                                 .setToLowerCase("L".equals(matcher.group(12))));
      }
    }
    return rules;
  }
}
