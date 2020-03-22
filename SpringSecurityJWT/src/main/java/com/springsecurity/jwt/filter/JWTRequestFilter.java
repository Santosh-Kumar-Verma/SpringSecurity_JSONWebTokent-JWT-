package com.springsecurity.jwt.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.springsecurity.jwt.service.MyUserDetailsService;
import com.springsecurity.jwt.util.JWTUtils;

@Component
public class JWTRequestFilter extends OncePerRequestFilter {

	@Autowired
	MyUserDetailsService myUserDetailsService;

	@Autowired
	JWTUtils jwtUtils;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

		final String authenticationRequest = request.getHeader("Authorization");
		String userName = null;
		String jwt = null;
		if (authenticationRequest != null && authenticationRequest.startsWith("Bearer")) {
			jwt = authenticationRequest.substring(7);
			userName = jwtUtils.extractUsername(jwt);
		}
		if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetails = this.myUserDetailsService.loadUserByUsername(userName);
			if (jwtUtils.validateToken(jwt, userDetails)) {
				UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authenticationToken);
			}

		}
		filterChain.doFilter(request, response);
	}

}
