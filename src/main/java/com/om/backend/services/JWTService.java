package com.om.backend.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JWTService {

    private  String secretKey = "f93c9b55c8d00c302bc7aee3c87b707cb96b0465d64ac3bc85955d4396e1e3de";
    public String generateToken(CustomUserDetails user){
        Map<String, Object> claims= new HashMap<>();
        claims.put("userId", user.getId());
        return Jwts.builder()
                .claims()
                .add(claims)
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()+ 180 * 24 * 60 * 60 * 1000))
                .and()
                .signWith(getKey())
                .compact();
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 182 * 24 * 60 * 60 * 1000)) // 7 days
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    public String resolveUsernameFromPrincipal(Object principal) {
        if (principal == null) throw new IllegalArgumentException("principal is null");
        if (principal instanceof com.om.backend.services.CustomUserDetails cud) {
            return cud.getUsername(); // your CustomUserDetails
        }
        if (principal instanceof org.springframework.security.core.userdetails.UserDetails ud) {
            return ud.getUsername();
        }
        if (principal instanceof String s) {
            return s; // sometimes principal is a raw username
        }
        throw new IllegalArgumentException("Unsupported principal type: " + principal.getClass());
    }


    public SecretKey getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractPhonenumber(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public boolean validToken(String token, UserDetails userDetails) {
        final String userName = extractPhonenumber(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }


    public boolean isTokenExpired(String token) {
        return  extractExpriation(token).before(new Date());
    }

    private Date extractExpriation(String token) {
        return  extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
           return Jwts.parser().verifyWith(getKey())
                    .build()
                    .parseSignedClaims(token).getPayload();
    }
}
