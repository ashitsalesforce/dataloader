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
import com.salesforce.dataloader.util.OAuthDeviceFlowUtil;
import com.salesforce.dataloader.util.OAuthBrowserDeviceLoginRunner;
import com.salesforce.dataloader.controller.Controller;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.Duration;
import java.util.*;

import static org.junit.Assert.assertTrue;

/**
 * End-to-end test for Salesforce OAuth Device Flow using Selenium (headless).
 *
 * Steps:
 * 1. Request device code from Salesforce.
 * 2. Automate browser to enter user code and approve.
 * 3. Poll for token.
 * 4. Validate granted scopes and access token.
 */
public class OAuthDeviceFlowTest extends ConfigTestBase {

    private String clientId;
    private String scopes;
    private String authEndpoint;
    private String deviceCodeUrl;
    private String tokenUrl;
    private String username;
    private String password;
    private String testApiEndpoint;

    private WebDriver driver;
    private WebDriverWait wait;

    @Before
    public void setUp() throws Exception {
        AppConfig appConfig = getController().getAppConfig();
        String env = appConfig.getString(AppConfig.PROP_SELECTED_SERVER_ENVIRONMENT);
        clientId = getDeviceClientId();
        authEndpoint = appConfig.getAuthEndpointForCurrentEnv();
        deviceCodeUrl = authEndpoint + "/services/oauth2/device/auth";
        tokenUrl = authEndpoint + "/services/oauth2/token";
        username = appConfig.getString(AppConfig.PROP_USERNAME);
        password = appConfig.getString(AppConfig.PROP_PASSWORD);
        scopes = "api";
        String apiVersion = Controller.getAPIVersion();
        testApiEndpoint = "/services/data/v" + apiVersion + "/sobjects/User";

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
    }
    
    /**
     * Helper: Poll for token using device code.
     */
    private JSONObject pollForToken(String deviceCode, int interval, int maxAttempts) throws Exception {
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            List<BasicNameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("grant_type", "urn:ietf:params:oauth:grant-type:device_code"));
            params.add(new BasicNameValuePair("client_id", clientId));
            params.add(new BasicNameValuePair("device_code", deviceCode));
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
                    System.out.println("[DeviceFlow] Poll attempt " + (attempt+1) + ": " + tokenResponse.toString(2));
                    if (tokenResponse.has("access_token")) {
                        return tokenResponse;
                    }
                }
            }
            Thread.sleep(interval * 1000L);
        }
        throw new RuntimeException("Did not receive access token after polling");
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
                return status == 200 || status == 201 || status == 204 || status == 400;
            }
        }
    }

    /**
     * Test Device Flow end-to-end.
     */
    @Ignore
    public void testDeviceFlow() throws Exception {
        // Step 1: Request device code using shared utility
        JSONObject deviceResponse = OAuthDeviceFlowUtil.requestDeviceCode(clientId, scopes, deviceCodeUrl);
        String userCode = deviceResponse.getString("user_code");
        String verificationUri = deviceResponse.getString("verification_uri");
        int interval = deviceResponse.optInt("interval", 5);
        String deviceCode = deviceResponse.getString("device_code");
        System.out.println("[DeviceFlow] User code: " + userCode);
        System.out.println("[DeviceFlow] Verification URI: " + verificationUri);

        // Step 2: Automate browser to enter user code and approve
        driver.get(verificationUri);
        System.out.println("[DeviceFlow] Waiting for user code entry field...");
        WebElement codeField = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("userCodeInput")));
        codeField.sendKeys(userCode);
        WebElement continueButton = wait.until(ExpectedConditions.elementToBeClickable(By.id("userCodeInputButton")));
        continueButton.click();
        // Salesforce login page
        System.out.println("[DeviceFlow] Waiting for username field...");
        WebElement usernameField = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("username")));
        WebElement passwordField = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("password")));
        usernameField.sendKeys(username);
        passwordField.sendKeys(password);
        WebElement loginButton = wait.until(ExpectedConditions.elementToBeClickable(By.id("Login")));
        loginButton.click();
        // Consent screen (if present)
        try {
            System.out.println("[DeviceFlow] Waiting for consent screen (if present)...");
            WebElement allowButton = wait.until(ExpectedConditions.elementToBeClickable(By.name("authorize")));
            System.out.println("[DeviceFlow] Clicking allow...");
            allowButton.click();
        } catch (Exception ignored) {
            System.out.println("[DeviceFlow] Consent screen not present or skipped.");
        }

        // Step 3: Poll for token using shared utility
        JSONObject tokenResponse = pollForToken(deviceCode, interval, 30);
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

    @Test
    public void testDeviceFlowWithRunner() throws Exception {
        AppConfig appConfig = getController().getAppConfig();
        // Enhanced handler: use Selenium to automate the full browser flow
        OAuthBrowserDeviceLoginRunner.VerificationUrlHandler seleniumHandler = url -> {
            // Extract user_code from the URL
            String userCode = null;
            try {
                java.net.URI uri = new java.net.URI(url);
                String query = uri.getQuery();
                if (query != null) {
                    for (String param : query.split("&")) {
                        String[] pair = param.split("=");
                        if (pair.length == 2 && pair[0].equals("user_code")) {
                            userCode = pair[1];
                        }
                    }
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to parse user_code from URL: " + url, e);
            }
            System.out.println("[DeviceFlowTest] Navigating Selenium to: " + url);
            driver.get(url);
            try {
                // Wait for the user_code field and click Connect if present
                if (driver.findElements(By.id("user_code")).size() > 0) {
                    WebElement codeField = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("user_code")));
                    codeField.clear();
                    codeField.sendKeys(userCode);
                    WebElement connectButton = wait.until(ExpectedConditions.elementToBeClickable(By.name("save")));
                    System.out.println("[DeviceFlowTest] Entered user code and clicking Connect...");
                    connectButton.click();

                    // Debug output after clicking Connect
                    System.out.println("[DeviceFlowTest] Current URL after Connect: " + driver.getCurrentUrl());
                    System.out.println("[DeviceFlowTest] Page source after Connect: " + driver.getPageSource());
                    java.util.List<WebElement> inputs = driver.findElements(By.tagName("input"));
                    for (WebElement input : inputs) {
                        System.out.println("[DeviceFlowTest] Input field: id=" + input.getAttribute("id") + ", name=" + input.getAttribute("name") + ", type=" + input.getAttribute("type"));
                    }
                }

                // Always wait for the login page after clicking Connect
                try {
                    WebElement usernameField = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("username")));
                    WebElement passwordField = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("password")));
                    System.out.println("[DeviceFlowTest] Login page detected, entering credentials...");
                    usernameField.sendKeys(username);
                    passwordField.sendKeys(password);
                    WebElement loginButton = wait.until(ExpectedConditions.elementToBeClickable(By.id("Login")));
                    loginButton.click();
                    // Fallback: also try submitting the form directly
                    try {
                        WebElement loginForm = driver.findElement(By.id("login_form"));
                        loginForm.submit();
                        System.out.println("[DeviceFlowTest] Submitted login form via form.submit().");
                    } catch (Exception e) {
                        System.out.println("[DeviceFlowTest] form.submit() failed: " + e.getMessage());
                    }
                    // Debug output after login attempt
                    System.out.println("[DeviceFlowTest] URL after login attempt: " + driver.getCurrentUrl());
                    System.out.println("[DeviceFlowTest] Page source after login attempt: " + driver.getPageSource());

                    // After login, wait for redirect to approval page or consent screen
                    try {
                        // Wait for either the consent button or the approval page URL
                        boolean approvalPage = wait.until(driver1 ->
                            driver1.getCurrentUrl().contains("RemoteAccessAuthorizationPage.apexp") ||
                            driver1.findElements(By.name("authorize")).size() > 0
                        );
                        System.out.println("[DeviceFlowTest] Approval page or consent screen detected.");
                        // Debug: print approval page source, all buttons, and forms
                        System.out.println("[DeviceFlowTest] Approval page source: " + driver.getPageSource());
                        java.util.List<WebElement> buttons = driver.findElements(By.tagName("button"));
                        for (WebElement button : buttons) {
                            System.out.println("[DeviceFlowTest] Button: name=" + button.getAttribute("name") + ", id=" + button.getAttribute("id") + ", text=" + button.getText());
                        }
                        java.util.List<WebElement> forms = driver.findElements(By.tagName("form"));
                        for (WebElement form : forms) {
                            System.out.println("[DeviceFlowTest] Form: name=" + form.getAttribute("name") + ", id=" + form.getAttribute("id") + ", action=" + form.getAttribute("action"));
                        }
                        // Try to extract the redirect URL from the script and navigate to it
                        String pageSource = driver.getPageSource();
                        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("window.location.replace\\([\"']([^\"']+)[\"']\\)").matcher(pageSource);
                        if (matcher.find()) {
                            String redirectUrl = matcher.group(1);
                            System.out.println("[DeviceFlowTest] Detected JS redirect, navigating to: " + redirectUrl);
                            driver.get(redirectUrl);
                            // Wait for either the consent button or a success/confirmation message
                            try {
                                boolean consentOrSuccess = wait.until(driver1 ->
                                    driver1.findElements(By.name("authorize")).size() > 0 ||
                                    driver1.findElements(By.cssSelector("input[type='submit'][name='save'][value*='Allow']")).size() > 0 ||
                                    driver1.getPageSource().toLowerCase().contains("success") ||
                                    driver1.getPageSource().toLowerCase().contains("authorized") ||
                                    driver1.getCurrentUrl().contains("success")
                                );
                                WebElement allowButton = null;
                                try {
                                    allowButton = wait.until(ExpectedConditions.elementToBeClickable(By.name("authorize")));
                                    System.out.println("[DeviceFlowTest] Classic consent screen detected, clicking Allow...");
                                } catch (Exception e1) {
                                    try {
                                        allowButton = wait.until(ExpectedConditions.elementToBeClickable(
                                            By.cssSelector("input[type='submit'][name='save'][value*='Allow']")));
                                        System.out.println("[DeviceFlowTest] New consent screen detected, clicking Allow...");
                                    } catch (Exception e2) {
                                        System.out.println("[DeviceFlowTest] Consent screen not present after redirect, assuming already authorized or success.");
                                        System.out.println("[DeviceFlowTest] Approval page source after redirect: " + driver.getPageSource());
                                    }
                                }
                                if (allowButton != null) {
                                    allowButton.click();
                                }
                            } catch (Exception e) {
                                System.out.println("[DeviceFlowTest] Consent/success screen not detected after redirect: " + e.getMessage());
                                System.out.println("[DeviceFlowTest] Approval page source after redirect: " + driver.getPageSource());
                            }
                        } else {
                            System.out.println("[DeviceFlowTest] No JS redirect found in approval page source.");
                        }
                    } catch (Exception e) {
                        System.out.println("[DeviceFlowTest] Approval page/consent screen not detected after login: " + e.getMessage());
                    }
                } catch (Exception e) {
                    System.out.println("[DeviceFlowTest] Login page not detected after Connect: " + e.getMessage());
                }
            } catch (Exception e) {
                System.out.println("[DeviceFlowTest] Selenium automation failed: " + e.getMessage());
                throw new RuntimeException(e);
            }
        };
        OAuthBrowserDeviceLoginRunner runner = new OAuthBrowserDeviceLoginRunner(appConfig, true, seleniumHandler);
        // Wait for login to complete (reuse logic from runner)
        int timeoutSeconds = appConfig.getOAuthTimeoutSeconds();
        int waited = 0;
        while (runner.getLoginStatus() == OAuthBrowserDeviceLoginRunner.LoginStatus.WAIT && waited < timeoutSeconds) {
            Thread.sleep(1000);
            waited++;
        }
        System.out.println("[DeviceFlowTest] Final login status: " + runner.getLoginStatus());
        assertTrue("Device flow did not succeed", runner.getLoginStatus() == OAuthBrowserDeviceLoginRunner.LoginStatus.SUCCESS);
    }
} 