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

package alluxio.security.group.provider;

import alluxio.Configuration;
import alluxio.PropertyKey;
import alluxio.security.group.GroupMappingService;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * A simple configuration-based implementation of {@link GroupMappingService} that fetch user's
 * groups information from configuration.
 */
public class ConfigBasedGroupsMapping implements GroupMappingService {

  /**
   * Constructs a new {@link ConfigBasedGroupsMapping}.
   */
  public ConfigBasedGroupsMapping() {}

  @Override
  public List<String> getGroups(String user) throws IOException {
    if (user == null || user.isEmpty()) {
      return null;
    }
    String groups =
        Configuration.get(PropertyKey.Template.SECURITY_USER_GROUP_MAPPING.format(user));
    return Arrays.asList(groups.split(","));
  }
}
