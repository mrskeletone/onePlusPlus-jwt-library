package com.hh.oneplusplus.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtFilter extends OncePerRequestFilter {
    private static final String AUTHORIZATION = "Authorization";

    private final JwtProvider jwtProvider;

    public JwtFilter(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = getTokenFromRequest(request);

        if (token != null && jwtProvider.validateAccessToken(token)
                && SecurityContextHolder.getContext().getAuthentication() == null) {

            JwtAuthentication jwtAuthentication = JwtAuthentication.generate(jwtProvider.getAccessClaims(token));
            String status = jwtAuthentication.getStatus();
            if(status.equals("BANNED")){
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.getWriter().write("Account banned");
                return;
            }
            SecurityContextHolder.getContext().setAuthentication(jwtAuthentication);

        }
        filterChain.doFilter(request, response);
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        String bearer = request.getHeader(AUTHORIZATION);
        if (StringUtils.hasText(bearer) && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }

}
