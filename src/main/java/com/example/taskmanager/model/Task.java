package com.example.taskmanager.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.LocalDate;
import java.time.LocalDateTime;

public class Task {
    private Long id;
    private String email;
    private String role;
    private String googleId;
    private LocalDateTime createDate;
    private LocalDateTime updateDate;
    private String fullName;
    private String status;
    private String phone;
    private String address;
    private LocalDate birthDate; // Thay LocalDateTime bằng LocalDate
    private String identityNumber;

    // Getters và setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
    @JsonProperty("GoogleID")
    public String getGoogleId() { return googleId; }
    public void setGoogleId(String googleId) { this.googleId = googleId; }
    @JsonProperty("CreateDate")
    public LocalDateTime getCreateDate() { return createDate; }
    public void setCreateDate(LocalDateTime createDate) { this.createDate = createDate; }
    @JsonProperty("UpdateDate")
    public LocalDateTime getUpdateDate() { return updateDate; }
    public void setUpdateDate(LocalDateTime updateDate) { this.updateDate = updateDate; }
    @JsonProperty("FullName")
    public String getFullName() { return fullName; }
    public void setFullName(String fullName) { this.fullName = fullName; }
    @JsonProperty("Status")
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    @JsonProperty("Phone")
    public String getPhone() { return phone; }
    public void setPhone(String phone) { this.phone = phone; }
    @JsonProperty("Address")
    public String getAddress() { return address; }
    public void setAddress(String address) { this.address = address; }
    @JsonProperty("BirthDate")
    public LocalDate getBirthDate() { return birthDate; } // Cập nhật getter
    public void setBirthDate(LocalDate birthDate) { this.birthDate = birthDate; } // Cập nhật setter
    @JsonProperty("IdentityNumber")
    public String getIdentityNumber() { return identityNumber; }
    public void setIdentityNumber(String identityNumber) { this.identityNumber = identityNumber; }


    public String getTitle() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void setTitle(String title) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void setDescription(String description) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void setCompleted(boolean selected) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public void setUpdatedAt(LocalDateTime now) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public boolean isCompleted() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public String getDescription() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}