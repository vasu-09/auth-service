package com.om.backend.services;

import com.om.backend.Dto.UserDTo;
import com.om.backend.Model.User;
import com.om.backend.Repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JWTService jwtService;
    @Autowired
    private UserSessionService userSessionService;

    public Map<String, String> login(UserDTo userDTo) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(userDTo.getPhoneNumber(), userDTo.getOtpCode())
        );

        CustomUserDetails user = (CustomUserDetails) authentication.getPrincipal();
        String phoneNumber = user.getUsername();

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        User user1 = getUser(phoneNumber);

        // You can store the refreshToken in DB via UserSessionService
        userSessionService.createOrUpdateSession(phoneNumber,  refreshToken, user1);

        return Map.of("accessToken", accessToken, "refreshToken", refreshToken);
    }

    public User getUser(String phoneNumber) {
       User user = userRepository.findByPhoneNumber(phoneNumber)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return user;
    }

    public ResponseEntity<List<Long>> getUserIdsByPhoneNumbers(List<String> phoneNumbers) {
        return new ResponseEntity<>(userRepository.findIdsByPhoneNumbers(phoneNumbers), HttpStatus.OK);
    }

    public ResponseEntity<Long> getUserIdByPhoneNumber(String phoneNumber) {
        return new ResponseEntity<>(userRepository.findUserIdByPhoneNumber(phoneNumber), HttpStatus.OK);
    }

    public ResponseEntity<String> getPhoneNumberByUserID(Long id) {

        return  new ResponseEntity<>(userRepository.findPhoneNumberByuserID(id), HttpStatus.OK);
    }

    public ResponseEntity<List<String>> getPhoneNumbersByIds(List<Long> id) {
        return new ResponseEntity<>(userRepository.findPhoneNumbersByIds(id), HttpStatus.OK);
    }

    public String getUserById(Long id) {
        User user= userRepository.findById(id).get();
        return  user.getUserName();
    }

    public User createUserWithPhone(String phoneNumber) {
        User u = new User();
        u.setPhoneNumber(phoneNumber);
        // Set any mandatory fields your entity requires:
        // u.setUserName("User_" + phoneNumber); // or derive a better default
        u.setCreatedAt(LocalDateTime.now());
        u.setActive(true);
        return userRepository.save(u);
    }
}
