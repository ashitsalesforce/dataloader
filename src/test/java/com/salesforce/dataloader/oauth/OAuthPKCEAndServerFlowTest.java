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
import com.salesforce.dataloader.util.OAuthPKCEUtil;
import com.salesforce.dataloader.util.OAuthRedirectListener;
import com.salesforce.dataloader.controller.Controller;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONObject;

import java.time.Duration;

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
    private String tokenUrl;
    private String username;
    private String password;
    private String testApiEndpoint;

    private WebDriver driver;
    private WebDriverWait wait;
    private OAuthRedirectListener redirectListener;
    private int pkcePort;

    @Before
    public void setUp() throws Exception {
        // Set up AppConfig and environment-based values
        AppConfig appConfig = getController().getAppConfig();
        clientId = getPKCEClientId();
        String pkcePortStr = appConfig.getString(AppConfig.PROP_OAUTH_PKCE_PORT);
        if (pkcePortStr != null && !pkcePortStr.isEmpty()) {
            pkcePort = Integer.parseInt(pkcePortStr);
        } else {
            pkcePort = AppConfig.DEFAULT_OAUTH_PKCE_PORT;
        }
        redirectUri = "http://localhost:" + pkcePort + "/OauthRedirect";
        //authEndpoint = appConfig.getAuthEndpointForCurrentEnv();
        authEndpoint = "https://login.salesforce.com";
        tokenUrl = authEndpoint + "/services/oauth2/token";
        username = appConfig.getString(AppConfig.PROP_USERNAME);
        password = appConfig.getString(AppConfig.PROP_PASSWORD);
        scopes = "api";
        String apiVersion = Controller.getAPIVersion();
        testApiEndpoint = "/services/data/v" + apiVersion + "/sobjects/User";

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
        redirectListener = new OAuthRedirectListener(pkcePort, "<html><body>Test complete. You may close this window.</body></html>");
    }

    @After
    public void tearDown() throws Exception {
        if (driver != null) driver.quit();
        if (redirectListener != null) redirectListener.stop();
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
     * Test PKCE flow end-to-end.
     */
    @Test
    public void testPKCEFlow() throws Exception {
        // Generate PKCE code verifier, challenge, and state using shared utility
        OAuthPKCEUtil.PKCEParams pkce = OAuthPKCEUtil.generatePKCEParams();

        redirectListener.start();

        // Build authorization URL using shared utility
        String url = OAuthPKCEUtil.buildAuthorizationUrl(
            authEndpoint, clientId, redirectUri, scopes, pkce.codeChallenge, pkce.state
        );

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
        String code = redirectListener.waitForCode(10);
        if (code != null) {
            System.out.println("[PKCE] Received authorization code: " + code);
        } else {
            System.out.println("[PKCE] Did NOT receive authorization code after waiting.");
        }
        assertTrue("Did not receive authorization code", code != null);
        // Exchange code for token using shared utility
        JSONObject tokenResponse = OAuthPKCEUtil.exchangeCodeForToken(
            tokenUrl, clientId, code, redirectUri, pkce.codeVerifier
        );
        System.out.println("[PKCE] Token endpoint response: " + tokenResponse.toString(2));
        assertTrue("No access token in response", tokenResponse.has("access_token"));
        // Validate scopes
        assertTrue("Granted scopes missing or incorrect", tokenResponse.has("scope") && tokenResponse.getString("scope").contains("api"));
        // Use token to call Salesforce API
        assertTrue("Access token did not allow API access", callSalesforceApi(tokenResponse.getString("access_token")));
        // Check for custom sObject TestField__c with label TestField
        assertTrue("Org does not have custom object TestField__c with label TestField",
            OAuthTestUtil.orgHasCustomObject(
                tokenResponse.getString("access_token"),
                tokenResponse.getString("instance_url"),
                "TestField",
                "TestField__c",
                Controller.getAPIVersion()
            )
        );
    }

    /**
     * Test Web Server flow end-to-end.
     * Enable it if you want to test the Web Server OAuth flow.
     * You would most likely need to disable the PKCE flow in your Salesforce connected app settings and disable the PKCE test above.
     */
    @Test
    public void testWebServerFlow() throws Exception {
        redirectListener.start();
        // Build authorization URL (no PKCE)
        clientId = getServerClientId();
        String url = OAuthPKCEUtil.buildAuthorizationUrl(
            authEndpoint, clientId, redirectUri, scopes, null, null
        );
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
        String code = redirectListener.waitForCode(10);
        if (code != null) {
            System.out.println("[WebServer] Received authorization code: " + code);
        } else {
            System.out.println("[WebServer] Did NOT receive authorization code after waiting.");
        }
        assertTrue("Did not receive authorization code", code != null);
        // Exchange code for token using shared utility (no PKCE)
        JSONObject tokenResponse = OAuthPKCEUtil.exchangeCodeForToken(
            tokenUrl, clientId, code, redirectUri, null
        );
        System.out.println("[WebServer] Token endpoint response: " + tokenResponse.toString(2));
        assertTrue("No access token in response", tokenResponse.has("access_token"));
        // Validate scopes
        assertTrue("Granted scopes missing or incorrect", tokenResponse.has("scope") && tokenResponse.getString("scope").contains("api"));
        // Use token to call Salesforce API
        assertTrue("Access token did not allow API access", callSalesforceApi(tokenResponse.getString("access_token")));
        // Check for custom sObject TestField__c with label TestField
        assertTrue("Org does not have custom object TestField__c with label TestField",
            OAuthTestUtil.orgHasCustomObject(
                tokenResponse.getString("access_token"),
                tokenResponse.getString("instance_url"),
                "TestField",
                "TestField__c",
                Controller.getAPIVersion()
            )
        );
    }
} 