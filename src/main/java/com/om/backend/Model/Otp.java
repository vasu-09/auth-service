package com.om.backend.Model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Data
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Otp {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; // Unique OTP ID

    private String otpCode; // OTP code itself
    private String phoneNumber; // Phone number for which OTP is generated (in case the user tries from multiple devices)
    private LocalDateTime createdAt; // Timestamp when OTP was generated
    private LocalDateTime expiredAt; // Timestamp when OTP expires
    private boolean isUsed; // To track if OTP has been used for login

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user; // Link to the User entity, this OTP belongs to

    @PrePersist
    public void setExpiryTime() {
        this.expiredAt = LocalDateTime.now().plusMinutes(5); // Set expiry to 5 minutes from creation time
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getOtpCode() {
        return otpCode;
    }

    public void setOtpCode(String otpCode) {
        this.otpCode = otpCode;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getExpiredAt() {
        return expiredAt;
    }

    public void setExpiredAt(LocalDateTime expiredAt) {
        this.expiredAt = expiredAt;
    }

    public boolean isUsed() {
        return isUsed;
    }

    public void setUsed(boolean used) {
        isUsed = used;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
