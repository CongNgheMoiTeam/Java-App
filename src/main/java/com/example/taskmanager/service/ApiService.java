package com.example.taskmanager.service;

import com.example.taskmanager.config.ApiConfig;
import com.example.taskmanager.model.Task;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.List;

public class ApiService {
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final ApiConfig apiConfig;
    private final AuthService authService;

    public ApiService(AuthService authService) {
        this.authService = authService;
        this.apiConfig = ApiConfig.getInstance();
        this.objectMapper = new ObjectMapper();
        this.objectMapper.findAndRegisterModules();
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(apiConfig.getConnectTimeout()))
                .build();
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

    public List<Task> getUsers() {
    try {
        String uri = apiConfig.getApiBaseUrl() + "/get";
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .header("Authorization", "Bearer " + authService.getAccessToken())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            return objectMapper.readValue(
                    response.body(),
                    new TypeReference<List<Task>>() {});
        } else {
            System.err.println("Error fetching users: " + response.statusCode() + " - " + response.body());
        }
    } catch (IOException | InterruptedException e) {
        e.printStackTrace();
    }
    return Collections.emptyList();
    }
    public Task createUser(Task user) {
        try {
            String requestBody = objectMapper.writeValueAsString(user);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiConfig.getApiBaseUrl() + "/add"))
                    .header("Authorization", "Bearer " + authService.getAccessToken())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return objectMapper.readValue(response.body(), Task.class);
            } else {
                System.err.println("Error creating user: " + response.statusCode() + " - " + response.body());
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        return null;
    }

    public Task updateUser(Task user) {
        try {
            String requestBody = objectMapper.writeValueAsString(user);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiConfig.getApiBaseUrl() + "/update"))
                    .header("Authorization", "Bearer " + authService.getAccessToken())
                    .header("Content-Type", "application/json")
                    .PUT(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return objectMapper.readValue(response.body(), Task.class);
            } else {
                System.err.println("Error updating user: " + response.statusCode() + " - " + response.body());
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean deleteUser(Long userId) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiConfig.getApiBaseUrl() + "/delete"))
                    .header("Authorization", "Bearer " + authService.getAccessToken())
                    .DELETE()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            return response.statusCode() == 200;
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return false;
        }
    }
}