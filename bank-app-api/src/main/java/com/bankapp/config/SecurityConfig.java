package com.bankapp.config;

import com.bankapp.filter.JWTGeneratorToken;
import com.bankapp.filter.JWTValidatorToken;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http
                .cors().and()
                .csrf().disable()
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests()
                .requestMatchers(
                        "/auth/signup",
                                "/auth/logout",
                                "/notices",
                                "/contact").permitAll()
                .anyRequest()
                .authenticated().and()
                .addFilterBefore(new JWTValidatorToken(), BasicAuthenticationFilter.class)
                .addFilterAfter(new JWTGeneratorToken(), BasicAuthenticationFilter.class)
                .httpBasic();
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
