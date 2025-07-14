/*
 * Copyright (c) 2015, salesforce.com, inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *    Redistributions of source code must retain the above copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 *    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
 *    the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 *    Neither the name of salesforce.com, inc. nor the names of its contributors may be used to endorse or
 *    promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package com.salesforce.dataloader.util;

import com.salesforce.dataloader.config.AppConfig;
import com.salesforce.dataloader.exception.ParameterLoadException;
import com.salesforce.dataloader.ui.Labels;
import com.salesforce.dataloader.ui.URLUtil;
import com.salesforce.dataloader.client.transport.SimplePostFactory;
import com.salesforce.dataloader.client.transport.SimplePostInterface;
import org.apache.http.message.BasicNameValuePair;
import org.apache.logging.log4j.Logger;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.FieldNamingPolicy;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URLEncoder;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import com.salesforce.dataloader.util.OAuthPKCEUtil;
import com.salesforce.dataloader.util.OAuthRedirectListener;
import java.text.MessageFormat;

/**
 * OAuth 2.0 Authorization Code Flow with PKCE implementation for server flow authentication.
 * This follows the same pattern as Salesforce CLI for maximum compatibility.
 */
public class OAuthServerFlow {
    private static final Logger logger = DLLogManager.getLogger(OAuthServerFlow.class);
    
    private static final String REDIRECT_URI_PATH = "/OauthRedirect"; // Same as Salesforce CLI
    
    private final AppConfig appConfig;
    private final java.util.function.Consumer<String> statusConsumer;
    private int port;
    private final boolean usePkce;
    private OAuthPKCEUtil.PKCEParams pkceParams;
    private OAuthRedirectListener redirectListener;
    private String authorizationCode;
    
    public OAuthServerFlow(AppConfig appConfig) throws ParameterLoadException {
        this(appConfig, true, null);
    }

    public OAuthServerFlow(AppConfig appConfig, boolean usePkce) throws ParameterLoadException {
        this(appConfig, usePkce, null);
    }

    public OAuthServerFlow(AppConfig appConfig, boolean usePkce, java.util.function.Consumer<String> statusConsumer) throws ParameterLoadException {
        this.appConfig = appConfig;
        this.usePkce = usePkce;
        this.statusConsumer = statusConsumer;
        this.port = findAvailablePort();
        if (this.port == 0) {
            throw new ParameterLoadException("No available port found for OAuth callback server");
        }
        logger.debug("Using port " + this.port + " for OAuth callback server");
    }
    
    /**
     * Performs the OAuth 2.0 Authorization Code Flow with PKCE.
     * 
     * @return true if OAuth flow completed successfully, false otherwise
     */
    public boolean performOAuthFlow() throws com.salesforce.dataloader.exception.ParameterLoadException, OAuthFlowNotEnabledException {
        int timeout = appConfig.getOAuthTimeoutSeconds();
        return performOAuthFlow(timeout);
    }
    
    /**
     * Performs the OAuth 2.0 Authorization Code Flow with PKCE.
     * 
     * @param timeoutSeconds Maximum time to wait for authorization
     * @return true if OAuth flow completed successfully, false otherwise
     */
    public boolean performOAuthFlow(int timeoutSeconds) throws com.salesforce.dataloader.exception.ParameterLoadException, OAuthFlowNotEnabledException {
        try {
            // Step 1: Generate PKCE parameters if needed
            if (usePkce) {
                pkceParams = OAuthPKCEUtil.generatePKCEParams();
                // codeVerifier = pkceParams.codeVerifier;
                // codeChallenge = pkceParams.codeChallenge;
                // state = pkceParams.state;
            } else {
                pkceParams = null;
                // state = OAuthPKCEUtil.generatePKCEParams().state;
                // codeVerifier = null;
                // codeChallenge = null;
            }
            // Step 2: Start local HTTP server using OAuthRedirectListener
            redirectListener = new OAuthRedirectListener(port, Labels.getString("OAuthServerFlow.successResponse"));
            redirectListener.start();
            // Step 3: Build authorization URL
            String authUrl = OAuthPKCEUtil.buildAuthorizationUrl(
                appConfig.getAuthEndpointForCurrentEnv(),
                appConfig.getEffectiveClientIdForCurrentEnv(),
                "http://localhost:" + port + REDIRECT_URI_PATH,
                "api",
                (pkceParams != null ? pkceParams.codeChallenge : null),
                (pkceParams != null ? pkceParams.state : null)
            );
            logger.info("Opening browser for OAuth authorization: " + authUrl);
            logger.info("OAuth client_id: " + appConfig.getEffectiveClientIdForCurrentEnv());
            logger.info("OAuth redirect_uri: http://localhost:" + port + REDIRECT_URI_PATH);
            if (statusConsumer != null) {
                statusConsumer.accept("A browser window has opened for login. If you do not see it, please check your pop-up blocker or open the following URL manually: " + authUrl);
            }
            // Step 4: Open browser
            URLUtil.openURL(authUrl);
            // Step 5: Wait for authorization callback
            logger.info("Waiting for OAuth authorization (timeout: " + timeoutSeconds + " seconds)...");
            String code = redirectListener.waitForCode(timeoutSeconds);
            if (code != null) {
                authorizationCode = code;
                // Step 6: Exchange authorization code for tokens
                return exchangeCodeForTokens();
            } else {
                logger.warn("OAuth authorization timed out or failed");
                if (statusConsumer != null) {
                    statusConsumer.accept("OAuth login timed out. Please complete the login in your browser, or check your network and try again.");
                }
                // Show error in browser
                String errorMsg = Labels.getString("OAuthServerFlow.errorResponseTemplate");
                errorMsg = MessageFormat.format(errorMsg, "OAuth login timed out or failed");
                // Start a new listener to show the error message
                OAuthRedirectListener errorListener = new OAuthRedirectListener(port, errorMsg);
                try {
                    errorListener.start();
                    // Wait briefly to allow browser to refresh and see the error
                    Thread.sleep(5000);
                } catch (Exception ignored) {} finally {
                    try { errorListener.stop(); } catch (Exception ignored) {}
                }
                return false;
            }
        } catch (com.salesforce.dataloader.exception.ParameterLoadException e) {
            throw e;
        } catch (OAuthFlowNotEnabledException e) {
            throw e;
        } catch (Exception e) {
            logger.error("OAuth browser flow failed", e);
            if (statusConsumer != null) {
                statusConsumer.accept("An unexpected error occurred during browser login: " + e.getMessage());
            }
            // Show error in browser
            String errorMsg = Labels.getString("OAuthServerFlow.errorResponseTemplate");
            errorMsg = MessageFormat.format(errorMsg, e.getMessage());
            // Start a new listener to show the error message
            OAuthRedirectListener errorListener = new OAuthRedirectListener(port, errorMsg);
            try {
                errorListener.start();
                // Wait briefly to allow browser to refresh and see the error
                Thread.sleep(5000);
            } catch (Exception ignored) {} finally {
                try { errorListener.stop(); } catch (Exception ignored) {}
            }
            return false;
        } finally {
            if (redirectListener != null) {
                try { redirectListener.stop(); } catch (Exception ignored) {}
            }
        }
    }
    
    /**
     * Exchanges the authorization code for access and refresh tokens.
     */
    private boolean exchangeCodeForTokens() throws com.salesforce.dataloader.exception.ParameterLoadException, OAuthFlowNotEnabledException {
        logger.info("Exchanging authorization code for tokens");
        try {
            String tokenUrl = appConfig.getAuthEndpointForCurrentEnv() + "/services/oauth2/token";
            String clientId = appConfig.getEffectiveClientIdForCurrentEnv();
            String redirectUri = "http://localhost:" + port + REDIRECT_URI_PATH;
            String codeVerifierToUse = usePkce && pkceParams != null ? pkceParams.codeVerifier : null;
            org.json.JSONObject tokenResponse = OAuthPKCEUtil.exchangeCodeForToken(
                tokenUrl, clientId, authorizationCode, redirectUri, codeVerifierToUse
            );
            if (tokenResponse != null && tokenResponse.has("access_token")) {
                String accessToken = tokenResponse.getString("access_token");
                String refreshToken = tokenResponse.optString("refresh_token", null);
                String instanceUrl = tokenResponse.optString("instance_url", null);
                appConfig.setValue(AppConfig.PROP_OAUTH_ACCESSTOKEN, accessToken);
                if (refreshToken != null) {
                    appConfig.setValue(AppConfig.PROP_OAUTH_REFRESHTOKEN, refreshToken);
                }
                if (instanceUrl != null) {
                    appConfig.setAuthEndpointForCurrentEnv(instanceUrl);
                    appConfig.setValue(AppConfig.PROP_OAUTH_INSTANCE_URL, instanceUrl);
                }
                logger.info("OAuth tokens obtained successfully using " +
                    (appConfig.isExternalClientAppConfigured() ? "External Client App" : "Connected App"));
                return true;
            } else {
                logger.error("Failed to obtain OAuth tokens: " + tokenResponse);
                return false;
            }
        } catch (com.salesforce.dataloader.exception.ParameterLoadException e) {
            throw e;
        } catch (OAuthFlowNotEnabledException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to exchange authorization code for tokens", e);
            return false;
        }
    }
    
    /**
     * Parses query string into key-value pairs.
     */
    private Map<String, String> parseQueryString(String query) {
        Map<String, String> params = new HashMap<>();
        if (query == null || query.trim().isEmpty()) {
            return params;
        }
        
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=", 2);
            if (keyValue.length == 2) {
                try {
                    String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8.name());
                    String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8.name());
                    params.put(key, value);
                } catch (Exception e) {
                    logger.debug("Error decoding query parameter: " + pair, e);
                }
            }
        }
        return params;
    }
    
    /**
     * Parse JSON response from OAuth endpoint.
     */
    private Map<?, ?> parseJsonResponse(InputStream inputStream) {
        try {
            StringBuilder builder = new StringBuilder();
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8.name()));
            for (int c = bufferedReader.read(); c != -1; c = bufferedReader.read()) {
                builder.append((char) c);
            }
            
            String jsonResponse = builder.toString();
            logger.debug("OAuth response: " + jsonResponse);
            
            Gson gson = new GsonBuilder()
                    .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                    .create();
            
            return gson.fromJson(jsonResponse, Map.class);
            
        } catch (Exception e) {
            logger.error("Failed to parse JSON response", e);
            return null;
        }
    }
    
    /**
     * Log error response for debugging.
     */
    private void logErrorResponse(InputStream inputStream) {
        try {
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            for (int length; (length = inputStream.read(buffer)) != -1; ) {
                result.write(buffer, 0, length);
            }
            String response = result.toString(StandardCharsets.UTF_8.name());
            logger.error("Error response: " + response);
        } catch (Exception e) {
            logger.debug("Could not read error response", e);
        }
    }
    
    /**
     * Finds an available port for the callback server.
     */
    private int findAvailablePort() {
        int preferredPort;
        try {
            preferredPort = appConfig.getInt(AppConfig.PROP_OAUTH_PKCE_PORT);
        } catch (Exception e) {
            logger.debug("Error reading OAuth PKCE port configuration, using default", e);
            preferredPort = AppConfig.DEFAULT_OAUTH_PKCE_PORT; // Default fallback
        }
        
        try (ServerSocket socket = new ServerSocket(preferredPort)) {
            return preferredPort;
        } catch (Exception e) {
			logger.fatal("PKCE port " + preferredPort + " is not available, searching for another port", e);
        }
        return 0;
    }
} 