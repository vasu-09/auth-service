package com.om.backend.Controllers;


import com.netflix.discovery.converters.Auto;
import com.om.backend.Config.OtpAuthenticationToken;
import com.om.backend.Dto.SendSmsResponse;
import com.om.backend.Dto.UserDTo;
import com.om.backend.services.*;
import com.om.backend.util.OtpMessageBuilder;
import com.om.backend.util.PhoneNumberUtil;
import com.om.backend.util.SmsClient;
import jakarta.validation.constraints.NotBlank;
import org.checkerframework.checker.units.qual.A;
import org.checkerframework.checker.units.qual.Area;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class OtpController {

    @Autowired
    private MyUserDetailsService userDetailsService;
   @Autowired
    private JWTService jwtService;
   @Autowired
    private  OtpService otpService;                     // send OTP via SMS
   @Autowired
    private  AuthenticationManager authenticationManager; // delegates to OtpAuthenticationProvider

    @Autowired
    private UserService userService;

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    /** Step 1: request OTP (sends SMS) */
    @PostMapping("/request")
    public ResponseEntity<?> request(@RequestParam String phone) {
        otpService.sendOtp(phone);
        return ResponseEntity.ok().build();
    }

    /** Step 2: authenticate with phone+otp (Provider validates & loads/creates user) */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String phone,
                                   @RequestParam String otp,
                                   @RequestParam int registrationId,
                                   @RequestParam(defaultValue = "1") int deviceId) {
        // 1) Authenticate (delegates to OtpAuthenticationProvider → validates OTP, loads/creates user)
        Authentication auth = authenticationManager.authenticate(
                OtpAuthenticationToken.unauthenticated(phone, otp)
        );

        var principal = (CustomUserDetails) auth.getPrincipal();
        Long userId = principal.getUser().getId();

        // 2) Issue short-lived access token
        String accessToken = jwtService.generateToken(principal); // your existing method

        // 3) Issue long-lived refresh token bound to device
        var issued = refreshTokenService.issue(userId, registrationId, deviceId, Duration.ofDays(90));
        String refreshToken = (String) issued.get("raw");

        // (Optional) set cookie instead of body:
        // ResponseCookie cookie = ResponseCookie.from("rt", refreshToken).httpOnly(true).secure(true)
        //      .sameSite("Strict").path("/auth/refresh").maxAge(Duration.ofDays(90)).build();

        return ResponseEntity.ok(Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken,
                "expiresAt", issued.get("expiresAt")
        ));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestParam String refreshToken,
                                     @RequestParam int registrationId,
                                     @RequestParam(defaultValue = "1") int deviceId) {
        try {
            // 1) verify & rotate the refresh token for this device
            var rotated = refreshTokenService.verifyAndRotate(refreshToken, registrationId, deviceId, Duration.ofDays(90));
            String newRefresh = (String) rotated.get("raw");

            // 2) Issue a new access token for that user
            // we need the user for access token; fetch via token hash lookup was done inside service.
            // simple approach: store userId inside the refresh token payload (signed) OR
            // return userId in the service; here's a pragmatic way:
            // Add a method to RefreshTokenService to resolve userId by current hash if needed,
            // or return it from verifyAndRotate alongside "raw".

            // For brevity, let’s add return of userId from service (update Map in service):
            // return Map.of("raw", raw, "expiresAt", ..., "id", e.getId(), "userId", userId);

            Long userId = (Long) rotated.get("userId");
            String username = userService.getUser(String.valueOf(userId)).getPhoneNumber(); // or a direct load of CustomUserDetails

            var userDetails = (CustomUserDetails) myUserDetailsService.loadUserByUsername(username);
            String newAccess = jwtService.generateToken(userDetails);

            return ResponseEntity.ok(Map.of(
                    "accessToken", newAccess,
                    "refreshToken", newRefresh,
                    "expiresAt", rotated.get("expiresAt")
            ));
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }
    }

    @PostMapping("/logout-device")
    public ResponseEntity<?> logoutDevice(@RequestParam int registrationId,
                                          @RequestParam(defaultValue = "1") int deviceId,
                                          @AuthenticationPrincipal CustomUserDetails me) {
        refreshTokenService.revokeAllForDevice(me.getUser().getId(), registrationId, deviceId);
        return ResponseEntity.ok().build();
    }

}
