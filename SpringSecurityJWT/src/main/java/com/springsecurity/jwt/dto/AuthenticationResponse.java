package com.springsecurity.jwt.dto;

public class AuthenticationResponse {

	private String  jwtTokent;

	public AuthenticationResponse(String jwtTokent) {
		this.jwtTokent = jwtTokent;
	}
	
	public String getJwtTokent() {
		return jwtTokent;
	}
}
