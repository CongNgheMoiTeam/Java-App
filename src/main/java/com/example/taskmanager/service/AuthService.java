package com.example.taskmanager.service;

import com.example.taskmanager.auth.GoogleLoginHelper;
import com.example.taskmanager.config.ApiConfig;
import com.example.taskmanager.config.DatabaseConfig;
import com.example.taskmanager.security.EncryptionUtil;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.services.oauth2.model.Userinfo;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.prefs.Preferences;

public class AuthService {
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final ApiConfig apiConfig;
    private final Preferences preferences;
    
    private String accessToken;
    private String refreshToken;
    private LocalDateTime expiryTime;
    
    private static final String PREF_ACCESS_TOKEN = "access_token";
    private static final String PREF_REFRESH_TOKEN = "refresh_token";
    private static final String PREF_EXPIRY_TIME = "expiry_time";

    public AuthService() {
        this.apiConfig = ApiConfig.getInstance();
        this.objectMapper = new ObjectMapper();
        this.preferences = Preferences.userNodeForPackage(AuthService.class);
        
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(apiConfig.getConnectTimeout()))
                .build();
                
        loadTokenFromPreferences();
    }
    
    private void loadTokenFromPreferences() {
        String encryptedAccessToken = preferences.get(PREF_ACCESS_TOKEN, null);
        String encryptedRefreshToken = preferences.get(PREF_REFRESH_TOKEN, null);
        String expiryTimeStr = preferences.get(PREF_EXPIRY_TIME, null);
        
        if (encryptedAccessToken != null && encryptedRefreshToken != null && expiryTimeStr != null) {
            this.accessToken = EncryptionUtil.decrypt(encryptedAccessToken);
            this.refreshToken = EncryptionUtil.decrypt(encryptedRefreshToken);
            this.expiryTime = LocalDateTime.parse(expiryTimeStr);
        }
    }
    
    private void saveTokenToPreferences() {
        if (accessToken != null && refreshToken != null && expiryTime != null) {
            preferences.put(PREF_ACCESS_TOKEN, EncryptionUtil.encrypt(accessToken));
            preferences.put(PREF_REFRESH_TOKEN, EncryptionUtil.encrypt(refreshToken));
            preferences.put(PREF_EXPIRY_TIME, expiryTime.toString());
        }
    }

    public String getAccessToken() {
        if (accessToken == null || expiryTime == null || LocalDateTime.now().isAfter(expiryTime)) {
            if (refreshToken != null) {
                refreshAccessToken();
            }
        }
        return accessToken;
    }
    
    // public boolean login(String username, String password) {
    //     return "admin".equals(username) && "1234".equals(password);
    // }
    
    private boolean refreshAccessToken() {
        try {
            String authHeader = "Basic " + Base64.getEncoder().encodeToString(
                    (apiConfig.getClientId() + ":" + apiConfig.getClientSecret()).getBytes()
            );
            
            Map<String, String> params = new HashMap<>();
            params.put("grant_type", "refresh_token");
            params.put("refresh_token", refreshToken);
            
            String formData = params.entrySet().stream()
                    .map(e -> e.getKey() + "=" + e.getValue())
                    .reduce((a, b) -> a + "&" + b)
                    .orElse("");
            
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiConfig.getApiBaseUrl() + "/refresh_token"))
                    .header("Authorization", authHeader)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(formData))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonNode jsonNode = objectMapper.readTree(response.body());
                processTokenResponse(jsonNode);
                return true;
            } else {
                System.err.println("Token refresh failed: " + response.statusCode() + " - " + response.body());
                this.accessToken = null;
                this.refreshToken = null;
                this.expiryTime = null;
                preferences.remove(PREF_ACCESS_TOKEN);
                preferences.remove(PREF_REFRESH_TOKEN);
                preferences.remove(PREF_EXPIRY_TIME);
                return false;
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    private void processTokenResponse(JsonNode jsonNode) {
        // this.accessToken = jsonNode.get("refresh_token").asText();
        // this.refreshToken = jsonNode.get("refresh_token").asText();
        // int expiresIn = jsonNode.get("expires_in").asInt(3600);
        //this.expiryTime = LocalDateTime.now().plusSeconds(expiresIn - 300);
        if (jsonNode.has("token")) {
            this.accessToken = jsonNode.get("token").asText();
            this.refreshToken = this.accessToken; // Nếu không có refresh_token riêng thì dùng luôn accessToken
            this.expiryTime = LocalDateTime.now().plusHours(1); // Có thể đọc từ "exp" nếu có
            saveTokenToPreferences();
        } else {
            System.err.println("No token found in token response: " + jsonNode.toPrettyString());
        }
        
    }
    
    public void logout() {
        this.accessToken = null;
        this.refreshToken = null;
        this.expiryTime = null;
        
        preferences.remove(PREF_ACCESS_TOKEN);
        preferences.remove(PREF_REFRESH_TOKEN);
        preferences.remove(PREF_EXPIRY_TIME);
        
        try {
            GoogleLoginHelper.clearStoredTokens();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public boolean isLoggedIn() {
        return (accessToken != null && expiryTime != null && LocalDateTime.now().isBefore(expiryTime));
    }

    public boolean loginWithGoogle(Userinfo userInfo) {
        try {
            System.out.println("Attempting Google login for user: " + (userInfo != null ? userInfo.getEmail() : "null"));
            if (userInfo == null || userInfo.getEmail() == null || userInfo.getId() == null) {
                System.out.println("Invalid Userinfo: " + (userInfo == null ? "null" : "email or ID missing"));
                return false;
            }

            // Tạo CSRF token
            String csrfToken = generateCsrfToken();
            System.out.println("Generated CSRF Token: " + csrfToken);

            String formData = "GoogleID=" + userInfo.getId() +
                    "&email=" + userInfo.getEmail() +
                    "&FullName=" + (userInfo.getName() != null ? userInfo.getName() : 
                        (userInfo.getGivenName() + " " + userInfo.getFamilyName())) +
                    "&access_token=google_" + System.currentTimeMillis() +
                    "&expires_at=" + LocalDateTime.now().plusHours(1).toString() +
                    "&csrf_token=" + csrfToken;

            String fullUrl = apiConfig.getApiBaseUrl() + "/login";
            System.out.println("Sending POST request to: " + fullUrl);
            System.out.println("Request body: " + formData);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(fullUrl))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Cookie", "csrf_token=" + csrfToken) // Gửi CSRF token trong cookie
                    .POST(HttpRequest.BodyPublishers.ofString(formData))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("Backend login response: " + response.body());

            if (response.statusCode() == 200) {
                JsonNode jsonNode = objectMapper.readTree(response.body());
                Map<String, Object> responseMap = parseJsonNode(jsonNode);
                System.out.println("Parsed Response Map: " + responseMap);
                if (jsonNode.has("token") || jsonNode.has("status")) {
                    this.accessToken = jsonNode.has("token") ? jsonNode.get("token").asText() : null;
                    this.refreshToken = this.accessToken;
                    this.expiryTime = LocalDateTime.now().plusHours(1);
                    saveTokenToPreferences();
                    System.out.println("Google login successful for user: " + userInfo.getEmail());
                    return true;
                } else {
                    System.err.println("No token in response: " + response.body());
                }
            } else {
                System.err.println("Backend login failed: " + response.statusCode() + " - " + response.body());
            }
        } catch (Exception e) {
            System.err.println("Google login failed: " + e.getMessage());
            e.printStackTrace();
        }
        return false;
    }

    private String generateCsrfToken() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getEncoder().encodeToString(randomBytes);
    }

    private boolean saveGoogleUserToDatabase(Userinfo userInfo) {
        return true;
    }
    public Map<String, Object> parseApiResponse(String json) {
    try {
        JsonNode rootNode = objectMapper.readTree(json);
        return parseJsonNode(rootNode);
    } catch (IOException e) {
        e.printStackTrace();
        return new HashMap<>();
    }
}

private Map<String, Object> parseJsonNode(JsonNode node) {
    Map<String, Object> result = new HashMap<>();
    node.fields().forEachRemaining(entry -> {
        String key = entry.getKey();
        JsonNode value = entry.getValue();
        if (value.isObject()) {
            result.put(key, parseJsonNode(value)); // đệ quy nếu là object lồng
        } else if (value.isArray()) {
            result.put(key, objectMapper.convertValue(value, Object[].class));
        } else if (value.isTextual()) {
            result.put(key, value.asText());
        } else if (value.isNumber()) {
            result.put(key, value.numberValue());
        } else if (value.isBoolean()) {
            result.put(key, value.asBoolean());
        } else {
            result.put(key, value.toString());
        }
    });
    return result;
}
}