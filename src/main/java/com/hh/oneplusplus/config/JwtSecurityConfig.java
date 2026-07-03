package com.hh.oneplusplus.config;

import com.hh.oneplusplus.jwt.JwtFilter;
import com.hh.oneplusplus.jwt.JwtProvider;
import com.hh.oneplusplus.service.SecurityContextService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtSecurityConfig {

    @Bean
    public JwtProvider jwtProvider(
            @Value("${jwt.access.secret-code}") String accessSecret,
            @Value("${jwt.refresh.secret-code}") String refreshSecret,
            @Value("${jwt.access.expire}") long accessExpire,
            @Value("${jwt.refresh.expire}") long refreshExpire) {
        return new JwtProvider(accessSecret, refreshSecret, accessExpire, refreshExpire);
    }

    @Bean
    public JwtFilter jwtFilter(JwtProvider jwtProvider) {
        return new JwtFilter(jwtProvider);
    }

    @Bean
    public SecurityContextService securityContextService() {
        return new SecurityContextService();
    }
}