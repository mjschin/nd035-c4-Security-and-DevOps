package com.example.demo.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.example.demo.model.requests.CreateUserRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.example.demo.model.persistence.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

/**
 * Processes an authentication form submission.
 *
 * Login forms must present two parameters to this filter: a username and password.
 * The default parameter names to use are contained in the static fields SPRING_SECURITY_FORM_USERNAME_KEY and
 * SPRING_SECURITY_FORM_PASSWORD_KEY. The parameter names can also be changed by setting the usernameParameter and
 * passwordParameter properties.
 *
 * This filter by default responds to the URL /login.
 */
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    //@Override
    // Performs actual authentication.
    //
    // It performs actual authentication by parsing (also called filtering) the user credentials.
    //
    // The implementation should do one of the following:
    //
    // - Return a populated authentication token for the authenticated user, indicating successful authentication
    // - Return null, indicating that the authentication process is still in progress. Before returning,
    // the implementation should perform any additional work required to complete the process.
    // - Throw an AuthenticationException if the authentication process fails.
    //
    // Specified by:
    // attemptAuthentication in class AbstractAuthenticationProcessingFilter
    //
    // Parameters:
    // request - from which to extract parameters and perform the authentication
    // response - the response, which may be needed if the implementation has to do a redirect as part of a multi-stage
    // authentication process (such as OpenID).
    //
    // Returns:
    // the authenticated user token, or null if authentication is incomplete.
    //
    // Throws:
    // AuthenticationException - if authentication fails.
    //
    public Authentication TMPattemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
        try {
            User credentials = new ObjectMapper()
                    .readValue(req.getInputStream(), User.class);

            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            credentials.getUsername(),
                            credentials.getPassword(),
                            new ArrayList<>()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
        try {
            CreateUserRequest creds =
                    new ObjectMapper().readValue(req.getInputStream(),
                            CreateUserRequest.class);
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            creds.getUsername(),
                            creds.getPassword() + new StringBuffer(creds.getUsername().toLowerCase()).reverse().toString(),
                            new ArrayList<>())
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    //
    // This is an override of method inherited from
    // class org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
    //
    // So, this method is originally present in the parent of the Base class. After overriding, this method will be
    // called after a user logs in successfully. Below, it is generating a String token (JWT) for this user.
    //
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {

        // Refer to the list of available algorithms, and the usage (create, verify, decode a token) of the above
        // library in the README : https://github.com/auth0/java-jwt/blob/master/README.md

        // Create and Sign a Token:
        // You'll first need to create a JWTCreator instance by calling JWT.create(). Use the builder to define the
        // custom Claims your token needs to have. Finally to get the String token call sign() and pass the Algorithm
        // instance.
        String token = JWT.create()
                .withSubject(((org.springframework.security.core.userdetails.User) auth.getPrincipal()).getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME))
                .sign(HMAC512(SecurityConstants.SECRET.getBytes()));
        res.addHeader(SecurityConstants.HEADER_STRING, SecurityConstants.TOKEN_PREFIX + token);
    }
}