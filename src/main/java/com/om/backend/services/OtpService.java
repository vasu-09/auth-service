package com.om.backend.services;

import com.om.backend.Config.SmsProperties;
import com.om.backend.util.OtpMessageBuilder;
import com.om.backend.util.PhoneNumberUtil;
import com.om.backend.util.SmsClient;
import lombok.RequiredArgsConstructor;

import org.apache.commons.lang.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class OtpService {
    @Autowired
    private  StringRedisTemplate redis;
    private  SmsProperties props;
    private  SmsClient smsClient;
    private  OtpMessageBuilder messageBuilder;

    /** Step 1: generate & send OTP via SMS */
    public void sendOtp(String rawPhone) {
        String phone = PhoneNumberUtil.toE164India(rawPhone);
        enforceRateLimits(phone);

        String otp = RandomStringUtils.randomNumeric(props.getOtp().getDigits());
        redis.opsForValue().set(otpKey(phone), otp, Duration.ofMinutes(props.getOtp().getTtlMinutes()));

        String msg = messageBuilder.build(otp);
        var res = smsClient.sendOtpMessage(msg, phone, true);
        if (!res.isOk()) {
            throw new RuntimeException("SMS send failed: " + res.getErrorDescription() + " (code " + res.getErrorCode() + ")");
        }
    }

    /** Step 2: validate during AuthenticationProvider */
    public boolean validateOtp(String rawPhone, String providedOtp) {
        String phone = PhoneNumberUtil.toE164India(rawPhone);
        String key = otpKey(phone);
        String expected = redis.opsForValue().get(key);
        if (expected != null && expected.equals(providedOtp)) {
            redis.delete(key); // one-time use
            return true;
        }
        return false;
    }

    private String otpKey(String e164Phone) { return "otp:" + e164Phone; }

    private void enforceRateLimits(String e164Mobile) {
        // per-minute
        String pmKey = "otp:rl:1m:" + e164Mobile;
        Long pm = redis.opsForValue().increment(pmKey);
        if (pm != null && pm == 1) redis.expire(pmKey, Duration.ofMinutes(1));
        if (pm != null && pm > props.getOtp().getPerMinuteLimit()) {
            throw new RateLimitException("Too many OTP requests. Try again in a minute.");
        }
        // per-hour
        String phKey = "otp:rl:1h:" + e164Mobile;
        Long ph = redis.opsForValue().increment(phKey);
        if (ph != null && ph == 1) redis.expire(phKey, Duration.ofHours(1));
        if (ph != null && ph > props.getOtp().getPerHourLimit()) {
            throw new RateLimitException("Too many OTP requests. Try again later.");
        }
    }

    public static class RateLimitException extends RuntimeException {
        public RateLimitException(String msg) { super(msg); }
    }
}