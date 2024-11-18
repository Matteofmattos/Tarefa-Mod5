package com.Matteof.mattos.DsEcommerce_Oauth2.dto;

import com.Matteof.mattos.DsEcommerce_Oauth2.entities.User;
import lombok.Getter;

@Getter
public class ClientDTO {

	private Long id;
	private String name;
	
	public ClientDTO(Long id, String name) {
		this.id = id;
		this.name = name;
	}
	
	public ClientDTO(User entity) {
		id = entity.getId();
		name = entity.getName();
	}

}
