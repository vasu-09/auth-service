package com.om.backend.Repositories;

import com.om.backend.Model.UserSession;
import jdk.jfr.Registered;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    Optional<UserSession> findByPhoneNumberAndIsActive(String phoneNumber, boolean active);
}
