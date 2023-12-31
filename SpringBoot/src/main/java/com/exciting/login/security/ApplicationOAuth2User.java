package com.exciting.login.security;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class ApplicationOAuth2User implements OAuth2User {
	
	private String member_id;
	private Collection<? extends GrantedAuthority> authorities;
	private Map<String, Object> attributes;
	
//	생성자
	public ApplicationOAuth2User(String member_id, Map<String, Object> attributes) {
		
		this.member_id = member_id;
		this.attributes = attributes;
		this.authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
		
	}
	
	@Override
	public Map<String,Object> getAttributes(){
		return this.attributes;
	}
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities(){
		return this.authorities;
	}
	
	@Override
	public String getName() {
		return this.member_id;
	}
	
	
}
