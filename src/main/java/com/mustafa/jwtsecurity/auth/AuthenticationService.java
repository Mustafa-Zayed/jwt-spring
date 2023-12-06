package com.mustafa.jwtsecurity.auth;

import com.mustafa.jwtsecurity.config.JwtService;
import com.mustafa.jwtsecurity.user.Role;
import com.mustafa.jwtsecurity.user.User;
import com.mustafa.jwtsecurity.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;// we created our bean of PasswordEncoder in ApplicationConfig class
    private final AuthenticationManager manager;// we created our bean of AuthenticationManager in ApplicationConfig class

    //this method will allow us to create a user, save it to the database
    //and return the generated token out of it.
    public AuthenticationResponse register(RegisterRequest request) {

        var user= User
                .builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))//encode before saving to database
                .role(Role.USER)
                .build();

        userRepository.save(user);

        String jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse
                .builder()
                .token(jwtToken)
                .build();
        // = return new AuthenticationResponse(jwtToken);
    }


    // this method will authenticate a user based on the username and password (i.e., AuthenticateRequest).
    public AuthenticationResponse authenticate(AuthenticateRequest request) {

        // this authentication manager will do all the job for me, and in case the
        // user's username or the password is not correct, so an exception would be thrown, 
        // so I'm totally secured when I just call this method.
        manager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()));

        // at this point here, the user is authenticated so the username and password are correct

        User user=userRepository
                .findUserByEmail(request.getEmail())
                .orElseThrow(()->new UsernameNotFoundException("The user not found in the database, sorry :("));

        String jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse
                .builder()
                .token(jwtToken)
                .build();
    }
}