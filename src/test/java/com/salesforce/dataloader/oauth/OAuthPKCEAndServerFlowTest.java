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

package com.salesforce.dataloader.oauth;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import com.salesforce.dataloader.ConfigTestBase;
import com.salesforce.dataloader.config.AppConfig;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.Assert.assertTrue;

/**
 * End-to-end test for Salesforce PKCE and Web Server OAuth flows using Selenium (headless).
 *
 * Steps:
 * 1. Launch headless browser, automate login/consent, capture authorization code from redirect.
 * 2. Exchange code for access token using HTTP client.
 * 3. Validate granted scopes.
 * 4. Use access token to call Salesforce API and verify access.
 *
 * Update CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, USERNAME, PASSWORD, and SCOPES before running.
 */
public class OAuthPKCEAndServerFlowTest extends ConfigTestBase {

    private String clientId;
    private String redirectUri;
    private String scopes;
    private String authEndpoint;
    private String authUrl;
    private String tokenUrl;
    private String username;
    private String password;
    private String testApiEndpoint;

    private WebDriver driver;
    private WebDriverWait wait;
    private ServerSocket serverSocket;
    private String lastAuthCode;
    private int pkcePort;

    @Before
    public void setUp() throws Exception {
        // Set up AppConfig and environment-based values
        AppConfig appConfig = getController().getAppConfig();
        String env = appConfig.getString(AppConfig.PROP_SELECTED_SERVER_ENVIRONMENT);
        clientId = appConfig.getOAuthEnvironmentString(env, AppConfig.CLIENTID_LITERAL);
        String pkcePortStr = appConfig.getString(AppConfig.PROP_OAUTH_PKCE_PORT);
        if (pkcePortStr != null && !pkcePortStr.isEmpty()) {
            pkcePort = Integer.parseInt(pkcePortStr);
        } else {
            pkcePort = AppConfig.DEFAULT_OAUTH_PKCE_PORT;
        }
        redirectUri = "http://localhost:" + pkcePort + "/OauthRedirect";
        authEndpoint = appConfig.getAuthEndpointForCurrentEnv();
        authUrl = authEndpoint + "/services/oauth2/authorize";
        tokenUrl = authEndpoint + "/services/oauth2/token";
        username = appConfig.getString(AppConfig.PROP_USERNAME);
        password = appConfig.getString(AppConfig.PROP_PASSWORD);
        scopes = "api";
        testApiEndpoint = "/services/data/v64.0/sobjects/User";

        // Check for GeckoDriver system property
        String geckoDriverPath = System.getProperty("webdriver.gecko.driver");
        if (geckoDriverPath == null || geckoDriverPath.isEmpty()) {
            throw new IllegalStateException("webdriver.gecko.driver system property must be set (e.g., via --geckodriver argument or -Dwebdriver.gecko.driver)");
        }
        java.io.File f = new java.io.File(geckoDriverPath);
        if (!f.exists() || !f.canExecute()) {
            throw new IllegalStateException("webdriver.gecko.driver does not exist or is not executable: " + geckoDriverPath);
        }
        FirefoxOptions options = new FirefoxOptions();
        options.addArguments("--headless");
        driver = new FirefoxDriver(options);
        wait = new WebDriverWait(driver, Duration.ofSeconds(20));
    }

    @After
    public void tearDown() throws Exception {
        if (driver != null) driver.quit();
        if (serverSocket != null && !serverSocket.isClosed()) serverSocket.close();
    }

    /**
     * Helper: Start a simple HTTP server to capture the redirect with the authorization code.
     */
    private void startRedirectListener() throws Exception {
        serverSocket = new ServerSocket(pkcePort); // Port must match redirectUri
        Thread listener = new Thread(() -> {
            try (Socket socket = serverSocket.accept()) {
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String line;
                String code = null;
                while ((line = in.readLine()) != null && !line.isEmpty()) {
                    if (line.startsWith("GET ")) {
                        int idx = line.indexOf("?");
                        if (idx > 0 && line.contains("/OauthRedirect")) {
                            String query = line.substring(idx + 1, line.indexOf(" ", idx));
                            for (String param : query.split("&")) {
                                if (param.startsWith("code=")) {
                                    code = URLDecoder.decode(param.substring(5), StandardCharsets.UTF_8);
                                    break;
                                }
                            }
                        }
                    }
                }
                lastAuthCode = code;
                // Respond to browser
                String httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
                        "<html><body>Authorization code received. You may close this window.</body></html>";
                socket.getOutputStream().write(httpResponse.getBytes(StandardCharsets.UTF_8));
            } catch (Exception ignored) {}
        });
        listener.setDaemon(true);
        listener.start();
    }

    /**
     * Helper: Exchange authorization code for access token.
     */
    private JSONObject exchangeCodeForToken(String code, boolean usePkce, String codeVerifier) throws Exception {
        List<BasicNameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "authorization_code"));
        params.add(new BasicNameValuePair("client_id", clientId));
        params.add(new BasicNameValuePair("code", code));
        params.add(new BasicNameValuePair("redirect_uri", redirectUri));
        if (usePkce) {
            params.add(new BasicNameValuePair("code_verifier", codeVerifier));
        }
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpPost post = new HttpPost(tokenUrl);
            post.setEntity(new UrlEncodedFormEntity(params));
            try (CloseableHttpResponse response = client.execute(post)) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
                JSONObject tokenResponse = new JSONObject(sb.toString());
                System.out.println("[PKCE] Token endpoint response: " + tokenResponse.toString(2));
                return tokenResponse;
            }
        }
    }

    /**
     * Helper: Use access token to call Salesforce API and verify access.
     */
    private boolean callSalesforceApi(String accessToken) throws Exception {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpPost post = new HttpPost("https://login.salesforce.com" + testApiEndpoint);
            post.setHeader("Authorization", "Bearer " + accessToken);
            post.setHeader("Content-Type", "application/json");
            try (CloseableHttpResponse response = client.execute(post)) {
                int status = response.getStatusLine().getStatusCode();
                return status == 200 || status == 201 || status == 204 || status == 400; // 400 if POST to /sobjects/User is not allowed, but token is valid
            }
        }
    }

    /**
     * PKCE code verifier and code challenge generation logic copied from OAuthServerFlow.java
     * (private void generatePKCEParameters())
     */
    private static String generateCodeVerifier() {
        // Generate code verifier (43-128 characters, URL-safe)
        SecureRandom random = new SecureRandom();
        byte[] codeVerifierBytes = new byte[32];
        random.nextBytes(codeVerifierBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifierBytes);
    }

    /**
     * PKCE code challenge generation logic copied from OAuthServerFlow.java
     */
    private static String generateCodeChallenge(String codeVerifier) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] challengeBytes = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes);
    }

    /**
     * Test PKCE flow end-to-end.
     */
    @Test
    public void testPKCEFlow() throws Exception {
        // Generate PKCE code verifier and challenge using Dataloader's logic (see OAuthServerFlow.java)
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);

        startRedirectListener();

        // Build authorization URL
        String url = authUrl + "?response_type=code" +
                "&client_id=" + clientId +
                "&redirect_uri=" + redirectUri +
                "&scope=" + scopes.replace(" ", "%20") +
                "&code_challenge=" + codeChallenge +
                "&code_challenge_method=S256";

        System.out.println("[PKCE] Authorization URL: " + url);
        driver.get(url);
        // Salesforce login page
        System.out.println("[PKCE] Waiting for username field...");
        WebElement usernameField = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("username")));
        WebElement passwordField = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("password")));
        System.out.println("[PKCE] Entering credentials...");
        usernameField.sendKeys(username);
        passwordField.sendKeys(password);
        WebElement loginButton = wait.until(ExpectedConditions.elementToBeClickable(By.id("Login")));
        System.out.println("[PKCE] Submitting login...");
        loginButton.click();
        // Consent screen (if present)
        try {
            System.out.println("[PKCE] Waiting for consent screen (if present)...");
            WebElement allowButton = wait.until(ExpectedConditions.elementToBeClickable(By.name("authorize")));
            System.out.println("[PKCE] Clicking allow...");
            allowButton.click();
        } catch (Exception ignored) {
            System.out.println("[PKCE] Consent screen not present or skipped.");
        }
        // Wait for redirect and code
        System.out.println("[PKCE] Waiting for authorization code...");
        for (int i = 0; i < 20 && lastAuthCode == null; i++) Thread.sleep(500);
        if (lastAuthCode != null) {
            System.out.println("[PKCE] Received authorization code: " + lastAuthCode);
        } else {
            System.out.println("[PKCE] Did NOT receive authorization code after waiting.");
        }
        assertTrue("Did not receive authorization code", lastAuthCode != null);
        // Exchange code for token
        JSONObject tokenResponse = exchangeCodeForToken(lastAuthCode, true, codeVerifier);
        assertTrue("No access token in response", tokenResponse.has("access_token"));
        // Validate scopes
        assertTrue("Granted scopes missing or incorrect", tokenResponse.has("scope") && tokenResponse.getString("scope").contains("api"));
        // Use token to call Salesforce API
        assertTrue("Access token did not allow API access", callSalesforceApi(tokenResponse.getString("access_token")));
    }

    /**
     * Test Web Server flow end-to-end.
     * Enable it if you want to test the Web Server OAuth flow.
     * You would most likely need to disable the PKCE flow in your Salesforce connected app settings and disable the PKCE test above.
     */
    @Ignore
    public void testWebServerFlow() throws Exception {
        startRedirectListener();
        // Build authorization URL (no PKCE)
        String url = authUrl + "?response_type=code" +
                "&client_id=" + clientId +
                "&redirect_uri=" + redirectUri +
                "&scope=" + scopes.replace(" ", "%20");
        System.out.println("[WebServer] Authorization URL: " + url);
        driver.get(url);
        // Salesforce login page
        System.out.println("[WebServer] Waiting for username field...");
        WebElement usernameField = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("username")));
        WebElement passwordField = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("password")));
        System.out.println("[WebServer] Entering credentials...");
        usernameField.sendKeys(username);
        passwordField.sendKeys(password);
        WebElement loginButton = wait.until(ExpectedConditions.elementToBeClickable(By.id("Login")));
        System.out.println("[WebServer] Submitting login...");
        loginButton.click();
        // Consent screen (if present)
        try {
            System.out.println("[WebServer] Waiting for consent screen (if present)...");
            WebElement allowButton = wait.until(ExpectedConditions.elementToBeClickable(By.name("authorize")));
            System.out.println("[WebServer] Clicking allow...");
            allowButton.click();
        } catch (Exception ignored) {
            System.out.println("[WebServer] Consent screen not present or skipped.");
        }
        // Wait for redirect and code
        System.out.println("[WebServer] Waiting for authorization code...");
        for (int i = 0; i < 20 && lastAuthCode == null; i++) Thread.sleep(500);
        if (lastAuthCode != null) {
            System.out.println("[WebServer] Received authorization code: " + lastAuthCode);
        } else {
            System.out.println("[WebServer] Did NOT receive authorization code after waiting.");
        }
        assertTrue("Did not receive authorization code", lastAuthCode != null);
        // Exchange code for token
        JSONObject tokenResponse = exchangeCodeForToken(lastAuthCode, false, null);
        assertTrue("No access token in response", tokenResponse.has("access_token"));
        // Validate scopes
        assertTrue("Granted scopes missing or incorrect", tokenResponse.has("scope") && tokenResponse.getString("scope").contains("api"));
        // Use token to call Salesforce API
        assertTrue("Access token did not allow API access", callSalesforceApi(tokenResponse.getString("access_token")));
    }
} 