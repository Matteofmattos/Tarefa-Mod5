package com.Matteof.mattos.DsEcommerce_Oauth2.controllers;

import com.Matteof.mattos.DsEcommerce_Oauth2.dto.UserDTO;
import com.Matteof.mattos.DsEcommerce_Oauth2.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/users")
public class UserController {

    @Autowired
    private UserService service;

    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_CLIENT')")
    @GetMapping(value = "/me")
    public ResponseEntity<UserDTO> getMe() {
    	UserDTO dto = service.getMe();
        return ResponseEntity.ok(dto);
    }
}
