package com.mustafa.jwtsecurity.config;

import com.mustafa.jwtsecurity.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository userRepository;

    @Bean
    public UserDetailsService userDetailsService(){

        return username -> userRepository.findUserByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("user not found"));
    }

    //Indicates a class can process a specific Authentication implementation(UserDetailsService and PasswordEncoder).
    @Bean
    public AuthenticationProvider authenticationProvider(){

        // this authentication provider is the data access object that is
        // responsible to fetch the user details and also encode password
        DaoAuthenticationProvider provider=new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService());// we need to tell this authentication provider which user details service to use in order to fetch information about our user because we might have multiple implementations of the user details one for getting the information from the database, in-memory database or from ldap
        provider.setPasswordEncoder(passwordEncoder());// the PasswordEncoder used to encode and validate passwords
        return provider;
    }

    // AuthenticationManager has a method called authenticate which used to authenticate a user based on the username and password i.e., responsible to manage and process an Authentication request
    // AuthenticationConfiguration exports the authentication Configuration (i.e., holds the information about the authentication manager)
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();// here we are using the default implementation of spring-boot, and this is sufficient for us
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
