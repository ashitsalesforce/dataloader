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

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.salesforce.dataloader.config.AppConfig;
import com.salesforce.dataloader.client.transport.SimplePostFactory;
import com.salesforce.dataloader.client.transport.SimplePostInterface;
import java.io.InputStream;

public class OAuthDeviceFlowUtil {
    public static JSONObject requestDeviceCode(String clientId, String scopes, String deviceCodeUrl) throws Exception {
        // This logic matches the original OAuthBrowserDeviceLoginRunner.java
        List<BasicNameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("client_id", clientId));
        params.add(new BasicNameValuePair("scope", scopes));
        System.out.println("[DeviceFlow] Device code URL: " + deviceCodeUrl);
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpPost post = new HttpPost(deviceCodeUrl);
            post.setEntity(new UrlEncodedFormEntity(params));
            try (CloseableHttpResponse response = client.execute(post)) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
                // No extra debug prints, just return the JSON as before
                JSONObject deviceResponse = new JSONObject(sb.toString());
                return deviceResponse;
            }
        }
    }

    public static Map<String, Object> requestDeviceCodeViaTokenEndpoint(AppConfig appConfig, String oAuthTokenURLStr) throws Exception {
        SimplePostInterface client = SimplePostFactory.getInstance(
            appConfig, oAuthTokenURLStr,
            new BasicNameValuePair("response_type", "device_code"),
            new BasicNameValuePair(AppConfig.CLIENT_ID_HEADER_NAME, appConfig.getEffectiveClientIdForCurrentEnv()),
            new BasicNameValuePair("scope", "api")
        );
        client.post();
        InputStream in = client.getInput();
        if (!client.isSuccessful()) {
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            for (int length; (length = in.read(buffer)) != -1; ) {
                result.write(buffer, 0, length);
            }
            String response = result.toString(StandardCharsets.UTF_8.name());
            result.close();
            throw new IOException(response);
        }
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(com.fasterxml.jackson.databind.DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);
        return mapper.readValue(in, Map.class);
    }

    public static JSONObject pollForToken(String clientId, String deviceCode, String tokenUrl, int interval, int maxAttempts) throws Exception {
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
                    if (tokenResponse.has("access_token")) {
                        return tokenResponse;
                    }
                }
            }
            Thread.sleep(interval * 1000L);
        }
        throw new RuntimeException("Did not receive access token after polling");
    }

    public static Map<String, Object> pollForTokenViaTokenEndpoint(AppConfig appConfig, String oAuthTokenURLStr, String deviceCode, int interval, int maxAttempts) throws Exception {
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            List<BasicNameValuePair> tokenParams = new ArrayList<>();
            tokenParams.add(new BasicNameValuePair("grant_type", "device"));
            tokenParams.add(new BasicNameValuePair(AppConfig.CLIENT_ID_HEADER_NAME, appConfig.getEffectiveClientIdForCurrentEnv()));
            tokenParams.add(new BasicNameValuePair("code", deviceCode));
            String clientSecret = appConfig.getEffectiveClientSecretForCurrentEnv();
            if (appConfig.isExternalClientAppConfigured() && clientSecret != null && !clientSecret.trim().isEmpty()) {
                tokenParams.add(new BasicNameValuePair("client_secret", clientSecret));
            }
            SimplePostInterface client = SimplePostFactory.getInstance(
                appConfig, oAuthTokenURLStr, tokenParams.toArray(new BasicNameValuePair[0])
            );
            client.post();
            InputStream in = client.getInput();
            if (client.isSuccessful()) {
                ObjectMapper mapper = new ObjectMapper();
                mapper.configure(com.fasterxml.jackson.databind.DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);
                return mapper.readValue(in, Map.class);
            } else {
                ObjectMapper mapper = new ObjectMapper();
                mapper.configure(com.fasterxml.jackson.databind.DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);
                Map<?, ?> responseMap = mapper.readValue(in, Map.class);
                System.err.println("[DeviceFlow] Polling error response: " + responseMap);
                String errorStr = (String)responseMap.get("error");
                if ("authorization_pending".equalsIgnoreCase(errorStr)) {
                    // continue polling
                } else {
                    throw new IOException(errorStr + " - " + responseMap.get("error_description"));
                }
            }
            Thread.sleep(interval * 1000L);
        }
        throw new RuntimeException("Did not receive access token after polling");
    }
} 