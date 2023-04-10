package com.bankapp.filter;

import com.bankapp.constants.Constants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class JWTValidatorToken extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // get header
        String header = request.getHeader(Constants.AUTHORIZATION);
        if(header != null) {
            try {
                // separete bearer from token
                String token = header.split(" ")[1];
                // get the secret key
                SecretKey key = Keys.hmacShaKeyFor(Constants.JWTKEY.getBytes(StandardCharsets.UTF_8));

                // get the claims and valid the token
                Claims claims = (Claims) Jwts.parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parse(token)
                        .getBody();

                String username = (String) claims.get("username");
                String authorities = (String) claims.get("authorities");

                // setting the user successfully
                SecurityContextHolder.getContext()
                        .setAuthentication(new UsernamePasswordAuthenticationToken(username,null, AuthorityUtils.commaSeparatedStringToAuthorityList(authorities)));
                System.out.println("User authenticated");
            } catch (Exception e) {
                throw new BadCredentialsException("Invalid token received");
            }
        }
        filterChain.doFilter(request,response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getServletPath().equals("/auth/login");
    }
}
