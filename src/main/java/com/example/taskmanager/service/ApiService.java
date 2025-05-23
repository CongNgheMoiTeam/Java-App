package com.example.taskmanager.service;

import com.example.taskmanager.config.ApiConfig;
import com.example.taskmanager.model.Task;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer;
import com.google.api.services.oauth2.model.Userinfo;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ApiService {
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final ApiConfig apiConfig;
    private final AuthService authService;
    private String csrfToken; // Lưu CSRF token

    public ApiService(AuthService authService) {
        this.authService = authService;
        this.apiConfig = ApiConfig.getInstance();
        this.objectMapper = new ObjectMapper();
        this.objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        JavaTimeModule javaTimeModule = new JavaTimeModule();
        javaTimeModule.addDeserializer(LocalDateTime.class, 
            new LocalDateTimeDeserializer(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
        javaTimeModule.addDeserializer(LocalDate.class, 
            new LocalDateDeserializer(DateTimeFormatter.ofPattern("yyyy-MM-dd")));
        this.objectMapper.registerModule(javaTimeModule);
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(apiConfig.getConnectTimeout()))
                .build();
        this.csrfToken = authService.generateCsrfToken(); // Sử dụng CSRF token từ AuthService
    }

//    public List<Task> getUsers() {
//        try {
//            HttpRequest request = HttpRequest.newBuilder()
//                    .uri(URI.create(apiConfig.getApiBaseUrl() + "/get"))
//                    .header("Authorization", "Bearer " + authService.getAccessToken())
//                    .header("Content-Type", "application/json")
//                    .GET()
//                    .build();
//
//            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
//
//            if (response.statusCode() == 200) {
//                return objectMapper.readValue(
//                        response.body(),
//                        new TypeReference<List<Task>>() {});
//            } else {
//                System.err.println("Error fetching users: " + response.statusCode() + " - " + response.body());
//            }
//        } catch (IOException | InterruptedException e) {
//            e.printStackTrace();
//        }
//        return Collections.emptyList();
//    }

//    public List<Task> getUsers() {
//    try {
//        String uri = apiConfig.getApiBaseUrl() + "/get";
//        HttpRequest request = HttpRequest.newBuilder()
//                .uri(URI.create(uri))
//                .header("Authorization", "Bearer " + authService.getAccessToken())
//                .header("Content-Type", "application/x-www-form-urlencoded")
//                .GET()
//                .build();
//
//        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
//
//        if (response.statusCode() == 200) {
//            return objectMapper.readValue(
//                    response.body(),
//                    new TypeReference<List<Task>>() {});
//        } else {
//            System.err.println("Error fetching users: " + response.statusCode() + " - " + response.body());
//        }
//    } catch (IOException | InterruptedException e) {
//        e.printStackTrace();
//    }
//    return Collections.emptyList();
//}
//    public Task getUsers() {
//    try {
//        String uri = apiConfig.getApiBaseUrl() + "/get";
//        System.out.println("Calling API: " + uri);
//        HttpRequest request = HttpRequest.newBuilder()
//                .uri(URI.create(uri))
//                .header("Authorization", "Bearer " + authService.getAccessToken())
//                .GET()
//                .build();
//
//        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
//        System.out.println("API Response: " + response.statusCode() + " - " + response.body());
//
//        if (response.statusCode() == 200) {
//            JsonNode rootNode = objectMapper.readTree(response.body());
//            if (rootNode.has("error")) {
//                System.err.println("API Error: " + rootNode.get("error").asText());
//                return null;
//            }
//            try {
//                Task task = objectMapper.readValue(response.body(), Task.class);
//                System.out.println("Task object: " + (task != null ? task.getEmail() : "null"));
//                return task;
//            } catch (JsonProcessingException e) {
//                System.err.println("Error parsing JSON: " + e.getMessage());
//                e.printStackTrace();
//                return null;
//            }
//        } else {
//            System.err.println("Error fetching users: " + response.statusCode() + " - " + response.body());
//        }
//    } catch (IOException | InterruptedException e) {
//        e.printStackTrace();
//    }
//    return null;
//}
public List<Task> getUsers() {
        try {
            String uri = apiConfig.getApiBaseUrl() + "/get";
            System.out.println("Calling API: " + uri);

            // Tạo Map chứa dữ liệu, bao gồm csrf_token
            Map<String, Object> data = new HashMap<>();
            data.put("csrf_token", csrfToken); // Thêm vào body JSON
            String requestBody = objectMapper.writeValueAsString(data);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(uri))
                    .header("Authorization", "Bearer " + authService.getAccessToken())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody)) // Chuyển sang POST
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("API Response: " + response.statusCode());
            System.out.println("Request body: " + requestBody);

            if (response.statusCode() == 200) {
                JsonNode rootNode = objectMapper.readTree(response.body());
                if (rootNode.has("error")) {
                    System.err.println("API Error: " + rootNode.get("error").asText());
                    return null;
                }
                try {
                    // Parse JSON array into List<Task>
                    List<Task> users = objectMapper.readValue(response.body(), 
                        objectMapper.getTypeFactory().constructCollectionType(List.class, Task.class));
                    System.out.println("Users fetched: " + (users != null ? users.size() : 0) + " users");
                    return users;
                } catch (JsonProcessingException e) {
                    System.err.println("Error parsing JSON: " + e.getMessage());
                    e.printStackTrace();
                    return null;
                }
            } else {
                System.err.println("Error fetching users: " + response.statusCode() + " - " + response.body());
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        return null;
    }
    // public List<Task> getUsers() {
    //     try {
    //         String uri = apiConfig.getApiBaseUrl() + "/get";
    //         System.out.println("Calling API: " + uri);
    //         HttpRequest request = HttpRequest.newBuilder()
    //                 .uri(URI.create(uri))
    //                 .header("Authorization", "Bearer " + authService.getAccessToken())
                    
    //                 .POST(HttpRequest.BodyPublishers.noBody())
    //                 .header("Content-Type", "application/x-www-form-urlencoded")
    //                 .build();
    //         //System.out.println("bla bla bla:"+authService.getAccessToken());

    //         HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    //         System.out.println("API Response: " + response.statusCode() + " - " + response.body());

    //         if (response.statusCode() == 200) {
    //             JsonNode rootNode = objectMapper.readTree(response.body());
    //             if (rootNode.has("error")) {
    //                 System.err.println("API Error: " + rootNode.get("error").asText());
    //                 return null;
    //             }
    //             try {
    //                 // Parse JSON array into List<Task>
    //                 List<Task> users = objectMapper.readValue(response.body(), 
    //                     objectMapper.getTypeFactory().constructCollectionType(List.class, Task.class));
    //                 System.out.println("Users fetched: " + (users != null ? users.size() : 0) + " users");
    //                 return users;
    //             } catch (JsonProcessingException e) {
    //                 System.err.println("Error parsing JSON: " + e.getMessage());
    //                 e.printStackTrace();
    //                 return null;
    //             }
    //         } else {
    //             System.err.println("Error fetching users: " + response.statusCode() + " - " + response.body());
    //         }
    //     } catch (IOException | InterruptedException e) {
    //         e.printStackTrace();
    //     }
    //     return null;
    // }
//    public List<Task> createUser(Task user) {
//        try {
//            String requestBody = objectMapper.writeValueAsString(user);
//            HttpRequest request = HttpRequest.newBuilder()
//                    .uri(URI.create(apiConfig.getApiBaseUrl() + "/add"))
//                    .header("Authorization", "Bearer " + authService.getAccessToken())
//                    .header("Content-Type", "application/json")
//                    .PUT(HttpRequest.BodyPublishers.ofString(requestBody))
//                    .build();
//
//            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
//            System.out.println("API Response: " + response.statusCode() + " - " + response.body());
//            System.out.println("Request body: " + requestBody);
//            if (response.statusCode() == 200) {
//                System.out.println("THÊM THÀNH CÔNG");
//                return (List<Task>) objectMapper.readValue(response.body(), Task.class);
//                
//            } else {
//                System.err.println("Error creating user: " + response.statusCode() + " - " + response.body());
//            }
//        } catch (IOException | InterruptedException e) {
//            e.printStackTrace();
//        }
//        return null;
//    }
//    public List<Task> updateUser(Task user) {
//            try {
//                String requestBody = objectMapper.writeValueAsString(user);
//                HttpRequest request = HttpRequest.newBuilder()
//                        .uri(URI.create(apiConfig.getApiBaseUrl() + "/AdminUpdate"))
//                        .header("Authorization", "Bearer " + authService.getAccessToken())
//                        .header("Content-Type", "application/json")
//                        .PUT(HttpRequest.BodyPublishers.ofString(requestBody))
//                        .build();
//
//                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
//                System.out.println("API Response: " + response.statusCode() + " - " + response.body());
//                System.out.println("Request body: " + requestBody);
//
//                if (response.statusCode() == 200) {
//                    try {
//                        List<Task> updatedUsers = objectMapper.readValue(response.body(),
//                                objectMapper.getTypeFactory().constructCollectionType(List.class, Task.class));
//                        System.out.println("Users updated: " + (updatedUsers != null ? updatedUsers.size() : 0) + " users");
//                        return updatedUsers;
//                    } catch (JsonProcessingException e) {
//                        System.err.println("Error parsing JSON to List<Task>: " + e.getMessage());
//                        e.printStackTrace();
//                        return null;
//                    }
//                } else {
//                    System.err.println("Error updating user: " + response.statusCode() + " - " + response.body());
//                }
//            } catch (IOException | InterruptedException e) {
//                e.printStackTrace();
//            }
//            return null;
//        }

//    public boolean createUser(Task user) {
//        try {
//            String requestBody = objectMapper.writeValueAsString(user);
//            HttpRequest request = HttpRequest.newBuilder()
//                    .uri(URI.create(apiConfig.getApiBaseUrl() + "/add"))
//                    .header("Authorization", "Bearer " + authService.getAccessToken())
//                    .header("Content-Type", "application/json")
//                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
//                    .build();
//
//            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
//            System.out.println("API Response: " + response.statusCode() + " - " + response.body());
//            System.out.println("Request body: " + requestBody);
//
//            if (response.statusCode() == 200) {
//                JsonNode jsonNode = objectMapper.readTree(response.body());
//                if (jsonNode.has("status") && "success".equals(jsonNode.get("status").asText())) {
//                    System.out.println("THÊM THÀNH CÔNG");
//                    return true;
//                } else {
//                    System.err.println("Error: " + (jsonNode.has("message") ? jsonNode.get("message").asText() : "Unknown error"));
//                    return false;
//                }
//            } else {
//                System.err.println("Error creating user: " + response.statusCode() + " - " + response.body());
//            }
//        } catch (IOException | InterruptedException e) {
//            e.printStackTrace();
//        }
//        return false;
//    }
//
//    public boolean updateUser(Task user) {
//        try {
//            String requestBody = objectMapper.writeValueAsString(user);
//            HttpRequest request = HttpRequest.newBuilder()
//                    .uri(URI.create(apiConfig.getApiBaseUrl() + "/AdminUpdate"))
//                    .header("Authorization", "Bearer " + authService.getAccessToken())
//                    .header("Content-Type", "application/json")
//                    .header("Cookie", "csrf_token=" + authService.generateCsrfToken()) // Sử dụng CSRF token từ AuthService
//                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
//                    .build();
//
//            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
//            System.out.println("API Response: " + response.statusCode() + " - " + response.body());
//            System.out.println("Request body: " + requestBody);
//
//            if (response.statusCode() == 200) {
//                JsonNode jsonNode = objectMapper.readTree(response.body());
//                if (jsonNode.has("status") && "success".equals(jsonNode.get("status").asText())) {
//                    System.out.println("CẬP NHẬT THÀNH CÔNG");
//                    return true;
//                } else {
//                    System.err.println("Error: " + (jsonNode.has("message") ? jsonNode.get("message").asText() : "Unknown error"));
//                    return false;
//                }
//            } else {
//                System.err.println("Error updating user: " + response.statusCode() + " - " + response.body());
//            }
//        } catch (IOException | InterruptedException e) {
//            e.printStackTrace();
//        }
//        return false;
//    }

    public boolean createUser(Task user) {
        try {
            // Chuyển đổi Task thành Map và thêm csrf_token
            Map<String, Object> data = objectMapper.convertValue(user, new TypeReference<Map<String, Object>>() {});
            data.put("csrf_token", csrfToken);
            // Đảm bảo CreateDate và updateDate là LocalDateTime
            if (user.getCreateDate() == null && user.getUpdateDate() == null) {
                LocalDateTime now = LocalDateTime.now();
                data.put("CreateDate", now.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
                data.put("updateDate", now.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            }
            String requestBody = objectMapper.writeValueAsString(data);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiConfig.getApiBaseUrl() + "/add"))
                    .header("Authorization", "Bearer " + authService.getAccessToken())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("API Response: " + response.statusCode() + " - " + response.body());
            System.out.println("Request body: " + requestBody);

            if (response.statusCode() == 200) {
                JsonNode jsonNode = objectMapper.readTree(response.body());
                if (jsonNode.has("status") && "success".equals(jsonNode.get("status").asText())) {
                    System.out.println("THÊM THÀNH CÔNG");
                    return true;
                } else {
                    System.err.println("Error: " + (jsonNode.has("message") ? jsonNode.get("message").asText() : "Unknown error"));
                    return false;
                }
            } else {
                System.err.println("Error creating user: " + response.statusCode() + " - " + response.body());
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean updateUser(Task user) {
        try {
            // Chuyển đổi Task thành Map và thêm csrf_token
            Map<String, Object> data = objectMapper.convertValue(user, new TypeReference<Map<String, Object>>() {});
            data.put("csrf_token", csrfToken);
            // Đảm bảo CreateDate và updateDate là chuỗi
            if (user.getCreateDate() != null) {
                data.put("createDate", user.getCreateDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            }
            if (user.getUpdateDate() != null) {
                data.put("updateDate", user.getUpdateDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            }
            if (user.getBirthDate() != null) {
                data.put("birthDate", user.getBirthDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd")));
            }
            String requestBody = objectMapper.writeValueAsString(data);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiConfig.getApiBaseUrl() + "/AdminUpdate"))
                    .header("Authorization", "Bearer " + authService.getAccessToken())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("API Response: " + response.statusCode() + " - " + response.body());
            System.out.println("Request body: " + requestBody);

            if (response.statusCode() == 200) {
                JsonNode jsonNode = objectMapper.readTree(response.body());
                if (jsonNode.has("status") && "success".equals(jsonNode.get("status").asText())) {
                    System.out.println("CẬP NHẬT THÀNH CÔNG");
                    return true;
                } else {
                    System.err.println("Error: " + (jsonNode.has("message") ? jsonNode.get("message").asText() : "Unknown error"));
                    return false;
                }
            } else {
                System.err.println("Error creating user: " + response.statusCode() + " - " + response.body());
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        return false;
    }
//    public boolean deleteUser(Long userId) {
//        try {
//            HttpRequest request = HttpRequest.newBuilder()
//                    .uri(URI.create(apiConfig.getApiBaseUrl() + "/delete"))
//                    .header("Authorization", "Bearer " + authService.getAccessToken())
//                    .DELETE()
//                    .build();
//
//            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
//
//            return response.statusCode() == 200;
//        } catch (IOException | InterruptedException e) {
//            e.printStackTrace();
//            return false;
//        }
//    }
//}
    public boolean deleteUser(Long userId) {
        try {
            // Tạo Map chứa dữ liệu, bao gồm id và csrf_token
            Map<String, Object> data = new HashMap<>();
            data.put("id", userId); // Gửi id qua body JSON
            data.put("csrf_token", csrfToken);
            String requestBody = objectMapper.writeValueAsString(data);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiConfig.getApiBaseUrl() + "/delete"))
                    .header("Authorization", "Bearer " + authService.getAccessToken())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("API Response: " + response.statusCode() + " - " + response.body());
            System.out.println("Request body: " + requestBody);

            if (response.statusCode() == 200) {
                JsonNode jsonNode = objectMapper.readTree(response.body());
                if (jsonNode.has("message") && "Xóa thành công".equals(jsonNode.get("message").asText())) {
                    System.out.println("XÓA THÀNH CÔNG");
                    return true;
                } else {
                    System.err.println("Error: " + (jsonNode.has("message") ? jsonNode.get("message").asText() : "Unknown error"));
                    return false;
                }
            } else {
                System.err.println("Error deleting user: " + response.statusCode() + " - " + response.body());
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        return false;
    }
}