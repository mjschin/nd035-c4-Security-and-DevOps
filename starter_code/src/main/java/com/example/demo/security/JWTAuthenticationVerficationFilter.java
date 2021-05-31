package com.example.demo.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

/**
 * This class is responsible for the authorization process. This class extends the BasicAuthenticationFilter class.
 * It overrides a method, and defines another custom method.
 */
@Component
public class JWTAuthenticationVerficationFilter extends BasicAuthenticationFilter {

    public JWTAuthenticationVerficationFilter(AuthenticationManager authManager) {
        super(authManager);
    }

    /**
     * Overridden method - doFilterInternal()- This method is used when we have multiple roles, and a policy for RBAC.
     * RBAC -> Role-Based Access Control.
     * @param req
     * @param res
     * @param chain
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        String header = req.getHeader(SecurityConstants.HEADER_STRING);

        if (header == null || !header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    /**
     * Custom method - getAuthentication() - It validates the token read from the Authorization header.
     *
     * "Authorization" header is provided when login is successful (see JWTAuthenticationFilter class)
     *
     * @param req
     * @return
     */
    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest req) {
        String token = req.getHeader(SecurityConstants.HEADER_STRING);
        if (token != null) {

            // Refer to the list of available algorithms, and the usage (create, verify, decode a token) of the above
            // library in the README : https://github.com/auth0/java-jwt/blob/master/README.md

            // Verify a Token:
            // You'll first need to create a JWTVerifier instance by calling JWT.require() and passing the Algorithm
            // instance. If you require the token to have specific Claim values, use the builder to define them.
            // The instance returned by the method build() is reusable, so you can define it once and use it to verify
            // different tokens. Finally call verifier.verify() passing the token.
            //
            String user = JWT.require(HMAC512(SecurityConstants.SECRET.getBytes())).build()
                    .verify(token.replace(SecurityConstants.TOKEN_PREFIX, ""))
                    .getSubject();
            if (user != null) {
                return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
            }
            return null;
        }
        return null;
    }

}