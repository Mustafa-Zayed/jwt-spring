package com.mustafa.jwtsecurity.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * When Spring Security starts and set up the application, it will use an object called UserDetails
 * and this UserDetails is an interface that contains a bunch of methods and each time you want to
 * work with Spring Security, you need to ensure that you are providing this UserDetails object
 * in order to make a Spring Security life easy to use. So to do this for our User, I recommend this
 * way, so every time you have a User think always to make it or to implement UserDetails interface,
 * so like that your User or your application is already a spring user.
 * <p>
 * <p>
 * You have two options whether you implement this UserDetails interface within your user class,
 * or you can create, for example, a User you call it app user and then extend the User class
 * the one from Spring Boot, so it will be the same.
 */

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "user")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String firstName;
    private String lastName;
    private String email;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
