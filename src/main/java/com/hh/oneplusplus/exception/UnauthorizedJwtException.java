package com.hh.oneplusplus.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class UnauthorizedJwtException extends RuntimeException{
    public UnauthorizedJwtException(String message) {
        super(message);
    }
}
