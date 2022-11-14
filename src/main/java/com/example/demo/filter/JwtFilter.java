package com.example.demo.filter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.example.demo.util.JwtUtil;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;


 
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = httpServletRequest.getHeader("Authorization");

        String token = null;
        String userName = null;
        System.out.print(authorizationHeader+"--------------------------------------------------");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            token = authorizationHeader.substring(7);
            userName = jwtUtil.extractUsername(token);
            System.out.println(">>>>>>>>>>>>>>>>>"+jwtUtil.extractAllClaims(token));
            System.out.println(jwtUtil.extractAllClaims(token).get("Role"));
     }
       System.out.print(userName+"-----------------------------------------------------------");
        if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {

           Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
     	  SimpleGrantedAuthority authority = new SimpleGrantedAuthority(jwtUtil.extractAllClaims(token).get("Role").toString());
     	  System.out.println(authority.getAuthority());
     	  authorities.add(authority);
            if (jwtUtil.validateToken(token)) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(jwtUtil.extractAllClaims(token), null, authorities);
                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
          
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}