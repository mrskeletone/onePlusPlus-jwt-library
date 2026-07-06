package com.hh.oneplusplus.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JwtProvider {


    private final long accessExpire;
    private final long refreshExpire;
    private final SecretKey accessSecretKey;
    private final SecretKey refreshSecretKey;
    private final Logger log = Logger.getLogger(String.valueOf(JwtProvider.class));

    public JwtProvider(String accessSecretCode, String refreshSecretCode, long accessExpire, long refreshExpire) {
        this.accessSecretKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(accessSecretCode));
        this.refreshSecretKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(refreshSecretCode));
        this.accessExpire = accessExpire;
        this.refreshExpire = refreshExpire;
    }

    public String createAccessToken(Map<String, Object> claims, String email) {
        LocalDateTime now = LocalDateTime.now();
        Instant accessExpirationInstant = now.plusMinutes(accessExpire).
                atZone(ZoneId.systemDefault()).toInstant();
        Date accessExpiration = Date.from(accessExpirationInstant);
        return Jwts.builder()
                .claims(claims)
                .subject(email)
                .expiration(accessExpiration)
                .signWith(accessSecretKey)
                .compact();
    }

    public String createRefreshToken(Map<String, Object> claims, String email, String jti) {
        LocalDateTime now = LocalDateTime.now();
        Instant refreshExpirationInstant = now.plusDays(refreshExpire).
                atZone(ZoneId.systemDefault()).toInstant();
        Date refreshExpiration = Date.from(refreshExpirationInstant);
        return Jwts.builder()
                .claims(claims)
                .subject(email)
                .id(jti)
                .expiration(refreshExpiration)
                .signWith(refreshSecretKey)
                .compact();
    }

    private boolean validateToken(String token, SecretKey key) {
        try {
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException expEx) {
            log.log(Level.INFO, "Token expired", expEx);
        } catch (UnsupportedJwtException unsEx) {
            log.log(Level.INFO, "Unsupported jwt", unsEx);
        } catch (MalformedJwtException mjEx) {
            log.log(Level.INFO, "Malformed jwt", mjEx);
        } catch (SignatureException sEx) {
            log.log(Level.INFO, "Invalid signature", sEx);
        } catch (Exception e) {
            log.log(Level.INFO, "invalid token", e);
        }
        return false;
    }

    public boolean validateAccessToken(String token) {
        return validateToken(token, accessSecretKey);
    }

    public boolean validateRefreshToken(String token) {
        return validateToken(token, refreshSecretKey);
    }

    private Claims getClaims(String token, SecretKey key) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Claims getAccessClaims(String token) {
        return getClaims(token, accessSecretKey);
    }

    public Claims getRefreshClaims(String token) {
        return getClaims(token, refreshSecretKey);
    }

    public int getRefreshExpireInSeconds() {
        return Math.toIntExact(refreshExpire * 24 * 60 * 60);
    }

}
