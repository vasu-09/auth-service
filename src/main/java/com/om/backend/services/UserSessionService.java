package com.om.backend.services;

import com.om.backend.Model.User;
import com.om.backend.Model.UserSession;
import com.om.backend.Repositories.UserSessionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class UserSessionService {
    @Autowired
    private UserSessionRepository userSessionRepository;

    public void createOrUpdateSession(String phoneNumber,  String token, User user1) {

        UserSession userSession = userSessionRepository.findByPhoneNumberAndIsActive(phoneNumber,  true).get();
        Optional.ofNullable(userSession)
                .ifPresent(s -> {
                    s.setActive(false);
                    userSessionRepository.save(s);
                });
        createUserSession(phoneNumber,token, user1);
    }

    private void createUserSession(String phoneNumber, String token, User user) {
        UserSession userSession = new UserSession();
        userSession.setCreatedAt(LocalDateTime.now());
        userSession.setExpiryTime();
        userSession.setUser(user);
        userSession.setSessionToken(token);
        userSession.setPhoneNumber(phoneNumber);
        userSession.setActive(true);
        userSessionRepository.save(userSession);
    }
}
