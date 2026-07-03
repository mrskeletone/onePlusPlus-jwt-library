package com.hh.oneplusplus.service;

import com.hh.oneplusplus.exception.UnauthorizedJwtException;
import com.hh.oneplusplus.jwt.JwtAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

public class SecurityContextService {

    private JwtAuthentication authentication() {
        Authentication authentication = SecurityContextHolder
                .getContext()
                .getAuthentication();
        if (authentication == null || !(authentication instanceof JwtAuthentication)) {
            throw new UnauthorizedJwtException("User not authenticated");
        }
        return (JwtAuthentication) authentication;
    }

    public Long getUserId() {
        return authentication().getUserId();
    }

    public String getEmail() {
        return authentication().getEmail();
    }

    public String getName() {
        return authentication().getName();
    }

    public String getSurname() {
        return authentication().getSurname();
    }
}
