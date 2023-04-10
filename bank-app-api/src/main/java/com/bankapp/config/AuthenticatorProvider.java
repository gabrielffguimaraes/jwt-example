package com.bankapp.config;

import com.bankapp.model.Customer;
import com.bankapp.service.CustomerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@Configuration
public class AuthenticatorProvider implements AuthenticationProvider {
    @Autowired
    private CustomerService customerService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        Customer customer = customerService.findByEmail(username);

        if(!passwordEncoder.matches(password,customer.getPassword())) {
            throw new BadCredentialsException("Username or password invalid !");
        }

        return new UsernamePasswordAuthenticationToken(username,customer.getPassword(),new ArrayList<>());
    }

    @Override
    public boolean supports(Class<?> authentication) {
       return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
