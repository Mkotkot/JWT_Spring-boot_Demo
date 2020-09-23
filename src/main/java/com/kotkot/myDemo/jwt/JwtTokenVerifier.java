package com.kotkot.myDemo.jwt;

import com.google.common.base.Strings;
import com.kotkot.myDemo.security.Constants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authenticationHeader = request.getHeader(Constants.AUTHENTICATION_HEADER);
        if (Strings.isNullOrEmpty(authenticationHeader) || !authenticationHeader.startsWith(Constants.TOKEN_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }
        String token = authenticationHeader.replace(Constants.TOKEN_PREFIX, "");

        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(Constants.SECRET_KEY_TEXT.getBytes()))
                    .build().parseClaimsJws(token);

            Claims claimsBody = claimsJws.getBody();
            String userName = claimsBody.getSubject();
            List<Map<String, String>> authorities = (List<Map<String, String>>) claimsBody.get(Constants.AUTHORITIES_BODY);
            Set<GrantedAuthority> authorityList = authorities.stream().map(auth -> new SimpleGrantedAuthority(auth.get("role"))).collect(Collectors.toSet());
            Authentication authentication = new UsernamePasswordAuthenticationToken(userName, null, authorityList);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JwtException e) {
            // May happen if the token InValid or Expired
            throw new IllegalStateException(String.format("Token %s can not be trusted ", token));
        }
        filterChain.doFilter(request, response);

    }


}

