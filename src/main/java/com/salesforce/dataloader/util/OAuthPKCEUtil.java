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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class OAuthPKCEUtil {
    public static class PKCEParams {
        public final String codeVerifier;
        public final String codeChallenge;
        public final String state;
        public PKCEParams(String codeVerifier, String codeChallenge, String state) {
            this.codeVerifier = codeVerifier;
            this.codeChallenge = codeChallenge;
            this.state = state;
        }
    }

    public static PKCEParams generatePKCEParams() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] codeVerifierBytes = new byte[32];
        random.nextBytes(codeVerifierBytes);
        String codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifierBytes);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] challengeBytes = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
        String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes);

        byte[] stateBytes = new byte[16];
        random.nextBytes(stateBytes);
        String state = Base64.getUrlEncoder().withoutPadding().encodeToString(stateBytes);

        return new PKCEParams(codeVerifier, codeChallenge, state);
    }

    public static String buildAuthorizationUrl(
        String authEndpoint, String clientId, String redirectUri, String scope,
        String codeChallenge, String state
    ) throws Exception {
        StringBuilder authUrl = new StringBuilder();
        authUrl.append(authEndpoint).append("/services/oauth2/authorize");
        authUrl.append("?response_type=code");
        authUrl.append("&client_id=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8.name()));
        authUrl.append("&redirect_uri=").append(URLEncoder.encode(redirectUri, StandardCharsets.UTF_8.name()));
        authUrl.append("&scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8.name()));
        if (codeChallenge != null) {
            authUrl.append("&code_challenge=").append(URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8.name()));
            authUrl.append("&code_challenge_method=S256");
        }
        if (state != null) {
            authUrl.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8.name()));
        }
        return authUrl.toString();
    }

    public static JSONObject exchangeCodeForToken(
        String tokenUrl, String clientId, String code, String redirectUri, String codeVerifier
    ) throws Exception {
        List<BasicNameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "authorization_code"));
        params.add(new BasicNameValuePair("client_id", clientId));
        params.add(new BasicNameValuePair("code", code));
        params.add(new BasicNameValuePair("redirect_uri", redirectUri));
        if (codeVerifier != null) {
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
                return new JSONObject(sb.toString());
            }
        }
    }
} 