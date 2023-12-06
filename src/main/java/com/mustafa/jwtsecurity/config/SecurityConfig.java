package com.mustafa.jwtsecurity.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * We need to tell spring which configuration that we want to use in order to make
 * all this works, so we created the filter, implemented the UserDetailsService
 * validation, updating SecurityContext and so on, but what we are missing is
 * The Binding we need to bind because we created a filter but this filter
 * is not yet used, so we need to use it
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authenticationProvider;

    /**
     * What I will need to do is create a bean of type SecurityFilterChain because at the
     * application startup, Spring Security will try to look for a bean of type SecurityFilterChain,
     * and it is the bean responsible for configuring all the HTTP security of our application.
     * It defines a filter chain which is capable of being matched against an HttpServletRequest in order to
     * decide whether it applies to that request.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            .csrf(csrf->csrf.disable())
            .authorizeHttpRequests(authorizeHttpRequests->
                    authorizeHttpRequests
                            .requestMatchers("/api/v1/auth/**")// for this list, I want to permit or whitelist all the requests (i.e., these requests are authorized)
                            .permitAll()
                            .anyRequest()// but all the other requests I want to authenticate them.
                            .authenticated())
            .sessionManagement(sessionManagement ->
                    sessionManagement
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS))// As OncePerRequestFilter means every request should be authenticated, this means that we should not store the authentication or session state, so the session should be stateless.
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)// I will use the method addFilterBefore because I want to execute JwtAuthenticationFilter filter before the filter called UsernamePasswordAuthenticationFilter because when we implemented the JwtAuthenticationFilter, we check everything, and then we update the SecurityContextHolder and after that we will be calling the UsernamePasswordAuthenticationFilter
        ;

        return http.build();
    }
}