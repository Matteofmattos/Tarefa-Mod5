package com.Matteof.mattos.DsEcommerce_Oauth2.service;

import com.Matteof.mattos.DsEcommerce_Oauth2.entities.User;
import com.Matteof.mattos.DsEcommerce_Oauth2.service.exceptions.ForbiddenException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

	@Autowired
	private UserService userService;
	
	public void validateSelfOrAdmin(long userId) {
		User me = userService.authenticated();
		if (!me.hasRole("ROLE_ADMIN") && !me.getId().equals(userId)) {
			throw new ForbiddenException(" # Access denied");
		}
	}
}
