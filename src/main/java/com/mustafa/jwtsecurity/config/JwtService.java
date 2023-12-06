package com.mustafa.jwtsecurity.config;

import io.jsonwebtoken.Claims;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private final static String SECRET_KEY="21d8482f3dfa0c7e18b394ae52e6375bfe672c46fd57a51b168304806b6eefd1";
    private Key getSignInKey() {
        byte[] keyBytes=Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
        //return Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <R> R extractClaim(String token, Function<Claims, R> claimsRFunction) {
        Claims claims=extractAllClaims(token);
        return claimsRFunction.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        return Jwts //factory class useful for creating instances of JWT interfaces
                .parserBuilder() //A parser for reading JWT strings, used to convert them into a Jwt object representing the expanded JWT.
                .setSigningKey(getSignInKey()) //the signing key used to verify any discovered JWS digital signature, verify the client identity, ensure that the message wasn't changed along the way
                .build()
                .parseClaimsJws(token) //parses the specified compact serialized JWS string and returns the resulting Claims JWS instance.
                .getBody(); // returns the JWT body, either a String or a Claims instance.    }
    }

// Note:- parserBuilder() or parser() used for reading JWT strings, but builder() used for constructing or creating JWTs

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+3600000))// 1 hour
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();// builds the JWT and serializes it to a compact, URL-safe string
    }

    /**
     * This method checks the client identity and the expiration date.
     * <p>
     * We need the userDetails because we want to validate if this token
     * belongs to that userDetails and not changed
     *
     * @author MustafaZ
     * @param token
     * @param userDetails
     * @return true if it's valid, else false
     */
    public boolean isTokenValid(String token, UserDetails userDetails){

        final String userName=extractUserName(token);
        return (userName.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

}
//allkeysgenerator.com/Random/Security-Encryption-Key-Generator.aspx