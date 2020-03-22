package com.springsecurity.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.springsecurity.jwt.dto.AuthenticationRequest;
import com.springsecurity.jwt.dto.AuthenticationResponse;
import com.springsecurity.jwt.dto.Employee;
import com.springsecurity.jwt.service.MyUserDetailsService;
import com.springsecurity.jwt.util.JWTUtils;

@RestController
public class HomeResource {

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	MyUserDetailsService myUserDetailsService;

	@Autowired
	JWTUtils jwtUtils;

	@PostMapping(value = "/Authenticate")
	public ResponseEntity<AuthenticationResponse> createAuthentickentTokent(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUserName(), authenticationRequest.getPassword()));
		} catch (Exception e) {
			throw new Exception("Incorrect userName and Password");
		}
		
		final UserDetails userDetails = myUserDetailsService.loadUserByUsername(authenticationRequest.getUserName());

		final String jwt = jwtUtils.generateToken(userDetails);
		return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}

	@GetMapping(value = "/getUserDetails")
	public Employee user() {
		return new Employee(100l, "USER");
	}
}
