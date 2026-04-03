/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.sql.common.interceptors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import lombok.NonNull;
import okhttp3.FormBody;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * OAuth2 Token Interceptor that dynamically fetches and caches OAuth2 tokens for Prometheus data
 * source authentication.
 */
public class OAuth2TokenInterceptor implements Interceptor {

  private final String clientId;
  private final String clientSecret;
  private final String tokenUrl;
  private final String scopes;
  private final String audience;
  private final OkHttpClient httpClient;
  private final ObjectMapper objectMapper;

  // Token cache with expiration
  private static final Map<String, TokenCache> tokenCache = new ConcurrentHashMap<>();

  private static class TokenCache {
    final String token;
    final Instant expiresAt;

    TokenCache(String token, long expiresInSeconds) {
      this.token = token;
      // Add 60 second buffer before expiration
      this.expiresAt = Instant.now().plusSeconds(expiresInSeconds - 60);
    }

    boolean isExpired() {
      return Instant.now().isAfter(expiresAt);
    }
  }

  public OAuth2TokenInterceptor(@NonNull Map<String, String> config) {
    this.clientId = config.get("prometheus.oauth2.clientId");
    this.clientSecret = config.get("prometheus.oauth2.clientSecret");
    this.tokenUrl = config.get("prometheus.oauth2.tokenUrl");
    this.scopes = config.get("prometheus.oauth2.scopes");
    this.audience = config.get("prometheus.oauth2.audience");
    this.httpClient = createHttpClientWithSSLConfig(config);
    this.objectMapper = new ObjectMapper();

    if (clientId == null || clientSecret == null || tokenUrl == null) {
      throw new IllegalArgumentException(
          "OAuth2 configuration incomplete: clientId, clientSecret, and tokenUrl are required");
    }
  }

  /**
   * Creates an OkHttpClient with SSL configuration that handles corporate certificates.
   *
   * @param config the configuration map
   * @return configured OkHttpClient
   */
  private OkHttpClient createHttpClientWithSSLConfig(Map<String, String> config) {
    OkHttpClient.Builder builder = new OkHttpClient.Builder();

    try {
      // Check if SSL bypass is enabled for development
      String sslBypass = config.get("prometheus.oauth2.ssl.bypass");
      if ("true".equalsIgnoreCase(sslBypass)) {
        // Create a trust manager that accepts all certificates (for development only)
        TrustManager[] trustAllCerts =
            new TrustManager[] {
              new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                  return new X509Certificate[] {};
                }
              }
            };

        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

        builder.sslSocketFactory(
            sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0]);
        builder.hostnameVerifier((hostname, session) -> true);
      } else {
        // Try to load custom certificates if specified
        String certPath = config.get("prometheus.oauth2.ssl.certPath");
        if (certPath != null && !certPath.isEmpty()) {
          try {
            KeyStore trustStore = loadCustomCertificates(certPath);
            TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);

            builder.sslSocketFactory(
                sslContext.getSocketFactory(), (X509TrustManager) tmf.getTrustManagers()[0]);
          } catch (Exception e) {
            // Log warning and fall back to default SSL configuration
            System.err.println(
                "Warning: Failed to load custom certificates from "
                    + certPath
                    + ": "
                    + e.getMessage());
          }
        }
      }
    } catch (Exception e) {
      // Log warning and use default SSL configuration
      System.err.println("Warning: Failed to configure SSL for OAuth2 client: " + e.getMessage());
    }

    return builder.build();
  }

  /**
   * Loads custom certificates from the specified path.
   *
   * @param certPath path to certificate file or directory
   * @return KeyStore with loaded certificates
   * @throws Exception if certificates cannot be loaded
   */
  private KeyStore loadCustomCertificates(String certPath) throws Exception {
    KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);

    File certFile = new File(certPath);
    if (certFile.isDirectory()) {
      // Load all .crt and .pem files from directory
      File[] certFiles =
          certFile.listFiles(
              (dir, name) ->
                  name.toLowerCase().endsWith(".crt") || name.toLowerCase().endsWith(".pem"));

      if (certFiles != null) {
        for (File file : certFiles) {
          loadCertificateFromFile(trustStore, file);
        }
      }
    } else if (certFile.exists()) {
      // Load single certificate file
      loadCertificateFromFile(trustStore, certFile);
    }

    return trustStore;
  }

  /**
   * Loads a certificate from a file into the trust store.
   *
   * @param trustStore the trust store to add the certificate to
   * @param certFile the certificate file
   * @throws Exception if the certificate cannot be loaded
   */
  private void loadCertificateFromFile(KeyStore trustStore, File certFile) throws Exception {
    try (FileInputStream fis = new FileInputStream(certFile)) {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
      trustStore.setCertificateEntry(certFile.getName(), cert);
    }
  }

  @Override
  public Response intercept(Chain chain) throws IOException {
    String token = getValidToken();

    Request originalRequest = chain.request();
    Request authenticatedRequest =
        originalRequest.newBuilder().header("Authorization", "Bearer " + token).build();

    return chain.proceed(authenticatedRequest);
  }

  private String getValidToken() throws IOException {
    String cacheKey = clientId + ":" + tokenUrl;
    TokenCache cached = tokenCache.get(cacheKey);

    if (cached != null && !cached.isExpired()) {
      return cached.token;
    }

    // Fetch new token
    String newToken = fetchOAuth2Token();
    return newToken;
  }

  private String fetchOAuth2Token() throws IOException {
    // Create HTTP Basic Auth header
    String credentials = clientId + ":" + clientSecret;
    String basicAuth = "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes());

    // Build form body
    FormBody.Builder formBuilder = new FormBody.Builder().add("grant_type", "client_credentials");

    if (scopes != null && !scopes.isEmpty()) {
      formBuilder.add("scope", scopes);
    }

    // Handle multiple audiences (Apple OAuth2 requirement)
    if (audience != null && !audience.isEmpty()) {
      String[] audiences = audience.split(",");
      for (String aud : audiences) {
        formBuilder.add("audience", aud.trim());
      }
    }

    Request tokenRequest =
        new Request.Builder()
            .url(tokenUrl)
            .header("Authorization", basicAuth)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .post(formBuilder.build())
            .build();

    try (Response response = httpClient.newCall(tokenRequest).execute()) {
      if (!response.isSuccessful()) {
        throw new IOException(
            "OAuth2 token request failed: " + response.code() + " " + response.message());
      }

      String responseBody = response.body().string();
      JsonNode jsonResponse = objectMapper.readTree(responseBody);

      String accessToken = jsonResponse.get("access_token").asText();
      long expiresIn =
          jsonResponse.has("expires_in") ? jsonResponse.get("expires_in").asLong() : 3600;

      // Cache the token
      String cacheKey = clientId + ":" + tokenUrl;
      tokenCache.put(cacheKey, new TokenCache(accessToken, expiresIn));

      return accessToken;
    }
  }
}
