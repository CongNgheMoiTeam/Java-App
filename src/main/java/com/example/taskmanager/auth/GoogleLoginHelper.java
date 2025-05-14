package com.example.taskmanager.auth;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.oauth2.Oauth2;
import com.google.api.services.oauth2.model.Userinfo;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

public class GoogleLoginHelper {
    private static final String CLIENT_ID = "";
    private static final String CLIENT_SECRET = "";
    private static final List<String> SCOPES = List.of(
            "https://www.googleapis.com/auth/userinfo.profile", 
            "https://www.googleapis.com/auth/userinfo.email");
    private static final String TOKENS_DIRECTORY_PATH = "tokens";

    /**
     * Performs Google OAuth2 authentication and returns user information
     */
    public static Userinfo login() throws Exception {
        System.out.println("Starting Google OAuth2 login process...");
        
        // Create HTTP Transport
        final NetHttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();
        System.out.println("HTTP Transport created successfully.");
        
        // Use GsonFactory for JSON parsing
        JsonFactory jsonFactory = GsonFactory.getDefaultInstance();
        System.out.println("JsonFactory created: " + jsonFactory.getClass().getName());
        
        // Create tokens directory if it doesn't exist
        File tokensDirectory = new File(TOKENS_DIRECTORY_PATH);
        if (!tokensDirectory.exists()) {
            tokensDirectory.mkdirs();
        }
        System.out.println("Tokens directory setup: " + tokensDirectory.getAbsolutePath());
        
        // Create GoogleClientSecrets from client ID and client secret
        String credentialsJson = String.format("""
        {
          "installed": {
            "client_id": "%s",
            "client_secret": "%s",
            "redirect_uris": ["http://localhost"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
          }
        }
        """, CLIENT_ID, CLIENT_SECRET);
        
        // Ensure UTF-8 for special characters
        ByteArrayInputStream in = new ByteArrayInputStream(credentialsJson.getBytes(StandardCharsets.UTF_8));
        GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(jsonFactory, new InputStreamReader(in, StandardCharsets.UTF_8));
        System.out.println("GoogleClientSecrets loaded.");
        
        // Create authentication flow
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                httpTransport, jsonFactory, clientSecrets, SCOPES)
                .setDataStoreFactory(new FileDataStoreFactory(new File(TOKENS_DIRECTORY_PATH)))
                .setAccessType("offline")
                .build();
        System.out.println("GoogleAuthorizationCodeFlow created.");
        
        // Receive authorization code from user using dynamic port
        LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(0).build();
        System.out.println("LocalServerReceiver created with dynamic port.");
        
        // Use AuthorizationCodeInstalledApp with prompt
        Credential credential = new AuthorizationCodeInstalledApp(flow, receiver) {
            @Override
            protected void onAuthorization(com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl authorizationUrl) throws IOException {
                authorizationUrl.set("prompt", "consent select_account"); // Force account chooser
                System.out.println("Authorization URL: " + authorizationUrl.build());
                super.onAuthorization(authorizationUrl);
            }
        }.authorize("user");
        
        // Debug: Check if credential is valid
        if (credential == null) {
            throw new Exception("Credential is null after authorization");
        }
        System.out.println("Credential obtained: " + credential.getAccessToken());
        
        // Get user information
        System.out.println("Creating Oauth2 service...");
        Oauth2 oauth2 = new Oauth2.Builder(httpTransport, jsonFactory, credential)
                .setApplicationName("Task Manager App")
                .build();
        System.out.println("Oauth2 service created.");
                
        System.out.println("Fetching user info...");
        Userinfo userinfo = oauth2.userinfo().get().execute();
        System.out.println("User info fetched: " + userinfo.getEmail());
        
        return userinfo;
    }

    /**
     * Clears stored OAuth2 tokens to allow login with a different account
     */
    public static void clearStoredTokens() throws Exception {
        File tokensDirectory = new File(TOKENS_DIRECTORY_PATH);
        if (tokensDirectory.exists() && tokensDirectory.isDirectory()) {
            File[] tokenFiles = tokensDirectory.listFiles();
            if (tokenFiles != null) {
                for (File tokenFile : tokenFiles) {
                    Files.deleteIfExists(tokenFile.toPath());
                }
            }
            // Optionally, delete the tokens directory itself
            Files.deleteIfExists(tokensDirectory.toPath());
        }
        System.out.println("Stored tokens cleared.");
    }
}