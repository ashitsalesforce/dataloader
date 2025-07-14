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

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;

public class OAuthRedirectListener {
    private final int port;
    private ServerSocket serverSocket;
    private String lastAuthCode;
    private Thread listenerThread;
    private final CountDownLatch codeLatch = new CountDownLatch(1);
    private final String htmlResponse; // Add this field

    public OAuthRedirectListener(int port, String htmlResponse) {
        this.port = port;
        this.htmlResponse = htmlResponse;
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        listenerThread = new Thread(() -> {
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
                codeLatch.countDown();
                // Respond to browser
                String httpResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + htmlResponse;
                socket.getOutputStream().write(httpResponse.getBytes(StandardCharsets.UTF_8));
            } catch (Exception ignored) {}
        });
        listenerThread.setDaemon(true);
        listenerThread.start();
    }

    public String waitForCode(int timeoutSeconds) throws InterruptedException {
        codeLatch.await(timeoutSeconds, java.util.concurrent.TimeUnit.SECONDS);
        return lastAuthCode;
    }

    public void stop() throws IOException {
        if (serverSocket != null && !serverSocket.isClosed()) serverSocket.close();
    }

    public String getLastAuthCode() {
        return lastAuthCode;
    }
} 