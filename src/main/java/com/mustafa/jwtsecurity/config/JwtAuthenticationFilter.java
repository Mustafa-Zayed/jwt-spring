package com.mustafa.jwtsecurity.config;

import com.mustafa.jwtsecurity.user.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * The filter is the first thing that gets executed within our application, and
 * this filter is an only once per-request filter because of extending
 * OncePerRequestFilter class and has the role to validate and check everything
 * regarding the token or the JWT token that we have
 */

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;


    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        //JWT token is within a header called Authorization,
        //so what we need to do here is try to extract this header
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;//also called userName

        //JWT token should start always with the keyword "Bearer "
        if (authHeader==null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);//pass the request and the response to the next filter
            return;
        }

        jwt=authHeader.substring(7);//because "Bearer " is 7 chars
        userEmail= jwtService.extractUserName(jwt);//extract the userEmail/userName from JWT token

        // Check that the user is not authenticated yet because if the user is
        // authenticated, I don't need to perform again all the checks and setting or
        // and updating the SecurityContext, all I need to do is leave it to the DispatcherServlet.
        // When the authentication is null, it means that the user
        // is not yet authenticated or connected
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication()==null){

            // So once the user is not connected, what we need to do here is check
            // or get the user from the database, so once we do this validation process,
            // we need to check if we have the user within the database.

            // At this level, we need to create a bean of type userDetailsService, or we need
            // to create a class that implements this interface and also give it
            // @Component or @Service annotation, so it becomes a managed bean and
            // spring will be able to inject.
            UserDetails userDetails= userDetailsService.loadUserByUsername(userEmail);//=userRepository.findUserByEmail(userEmail).get()

            // The next step is to validate and check if the token is still valid or not.
            // This method checks the client identity and the expiration date.
            // If the user is valid, we need to update the SecurityContext
            // and send the request to our DispatcherServlet.
            if(jwtService.isTokenValid(jwt, userDetails)){

                // Represents the token for an authentication request.
                // This object is needed by the SecurityContextHolder
                // in order to update our SecurityContext.
                UsernamePasswordAuthenticationToken authToken=new UsernamePasswordAuthenticationToken(
                        userDetails,null,userDetails.getAuthorities());

                // Stores additional details about the authentication request.
                // These might be an IP address, certificate serial number, etc.
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // Once the request has been authenticated, the Authentication will usually
                // be stored in a thread-local SecurityContext managed by the SecurityContextHolder
                // by the authentication mechanism which is being used.
                // Here, we store the new authentication token and authenticate the request.
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);

    }
}