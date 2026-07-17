package com.hh.oneplusplus.jwt;

import io.jsonwebtoken.Claims;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;

public class JwtAuthentication implements Authentication {
    private boolean authenticated;
    private String email;
    private String name;
    private long userId;
    private String surname;
    private String role;
    private String status;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role));
    }

    @Override
    public @Nullable Object getCredentials() {
        return null;
    }

    @Override
    public @Nullable Object getDetails() {
        return null;
    }

    @Override
    public @Nullable Object getPrincipal() {
        return email;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }

    public String getSurname() {
        return surname;
    }

    @Override
    public String getName() {
        return name;
    }

    public long getUserId() {
        return userId;
    }

    public void setUserId(long userId) {
        this.userId = userId;
    }

    public String getEmail() {
        return email;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public static JwtAuthentication generate(Claims claims) {
        JwtAuthentication jwtAuthentication = new JwtAuthentication();
        jwtAuthentication.setEmail(claims.getSubject());
        jwtAuthentication.setName(claims.get("name", String.class));
        jwtAuthentication.setSurname(claims.get("surname", String.class));
        jwtAuthentication.setUserId(claims.get("id", Long.class));
        jwtAuthentication.setRole(claims.get("role", String.class));
        jwtAuthentication.setStatus(claims.get("status", String.class));
        jwtAuthentication.setAuthenticated(true);
        return jwtAuthentication;
    }
}
