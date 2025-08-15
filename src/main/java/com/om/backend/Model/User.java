package com.om.backend.Model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Data
@Getter
@Setter
public class User {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id; // Unique user ID

        private String phoneNumber; // Phone number used for login
        private String userName; // Full name of the user
        private String email; // Optional, for recovery and notifications
        private String avatarUrl; // URL to the user's avatar image
        private boolean isActive; // Indicates if the user is active (if they are blocked or deactivated)
        private LocalDateTime createdAt; // When the user registered
        private LocalDateTime updatedAt; // Last time the user information was updated

        @OneToMany(mappedBy = "user")
        private List<Otp> otps; // List of OTPs generated for the user (1-to-many relationship)
        @OneToOne(cascade = CascadeType.ALL)
        @JoinColumn(name = "phone_verification_id", referencedColumnName = "id")
        private PhoneVerification phoneVerification; // Linking to PhoneVerification

        public Long getId() {
                return id;
        }

        public void setId(Long id) {
                this.id = id;
        }

        public String getPhoneNumber() {
                return phoneNumber;
        }

        public void setPhoneNumber(String phoneNumber) {
                this.phoneNumber = phoneNumber;
        }

        public String getUserName() {
                return userName;
        }

        public void setUserName(String userName) {
                this.userName = userName;
        }

        public String getEmail() {
                return email;
        }

        public void setEmail(String email) {
                this.email = email;
        }

        public String getAvatarUrl() {
                return avatarUrl;
        }

        public void setAvatarUrl(String avatarUrl) {
                this.avatarUrl = avatarUrl;
        }

        public boolean isActive() {
                return isActive;
        }

        public void setActive(boolean active) {
                isActive = active;
        }

        public LocalDateTime getCreatedAt() {
                return createdAt;
        }

        public void setCreatedAt(LocalDateTime createdAt) {
                this.createdAt = createdAt;
        }

        public LocalDateTime getUpdatedAt() {
                return updatedAt;
        }

        public void setUpdatedAt(LocalDateTime updatedAt) {
                this.updatedAt = updatedAt;
        }

        public List<Otp> getOtps() {
                return otps;
        }

        public void setOtps(List<Otp> otps) {
                this.otps = otps;
        }

        public PhoneVerification getPhoneVerification() {
                return phoneVerification;
        }

        public void setPhoneVerification(PhoneVerification phoneVerification) {
                this.phoneVerification = phoneVerification;
        }
}
