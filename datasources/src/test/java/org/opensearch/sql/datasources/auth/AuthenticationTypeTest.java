/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.sql.datasources.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class AuthenticationTypeTest {
  @Test
  void getAuthType() {
    assertEquals(
        AuthenticationType.BASICAUTH,
        AuthenticationType.get(AuthenticationType.BASICAUTH.getName()));
    assertEquals(
        AuthenticationType.AWSSIGV4AUTH,
        AuthenticationType.get(AuthenticationType.AWSSIGV4AUTH.getName()));
    assertEquals(
        AuthenticationType.OAUTH2,
        AuthenticationType.get(AuthenticationType.OAUTH2.getName()));
  }

  @Test
  void getNotExistAuthType() {
    assertNull(AuthenticationType.get("mock"));
  }
}
