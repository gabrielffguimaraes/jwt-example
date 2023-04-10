package com.bankapp.filter;

import com.bankapp.constants.Constants;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashSet;
import java.util.List;


public class JWTGeneratorToken extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication != null) {
            // hash the secret key
            SecretKey secretKey = Keys.hmacShaKeyFor(Constants.JWTKEY.getBytes(StandardCharsets.UTF_8));

            // generate jwt token
            String jwt = Jwts.builder()
                    .claim("username",authentication.getName())
                    .claim("authorities",String.join( ",", grantedAuthoritiesToString((List<GrantedAuthority>) authentication.getAuthorities())))
                    .setIssuer("Easy Bank")
                    .setSubject("JWT Token")
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(new Date().getTime() + 30000000))
                    .signWith(secretKey)
                    .compact();
            // set token to the header
            response.setHeader(Constants.AUTHORIZATION,jwt);
        }
        filterChain.doFilter(request,response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return !request.getServletPath().equals("/auth/login");
    }

    private String grantedAuthoritiesToString(List<GrantedAuthority> authorities) {
        HashSet<String> authoritiesString = new HashSet<>();
        for(GrantedAuthority grantedAuthority: authorities) {
            authoritiesString.add(grantedAuthority.getAuthority());
        }
        return String.join(",",authoritiesString);
    }
}
