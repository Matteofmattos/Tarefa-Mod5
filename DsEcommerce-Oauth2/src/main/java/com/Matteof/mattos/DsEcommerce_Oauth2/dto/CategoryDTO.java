package com.Matteof.mattos.DsEcommerce_Oauth2.dto;

import com.Matteof.mattos.DsEcommerce_Oauth2.entities.Category;
import lombok.Getter;

@Getter
public class CategoryDTO {

	private Long id;
	private String name;
	
	public CategoryDTO(Long id, String name) {
		this.id = id;
		this.name = name;
	}
	
	public CategoryDTO(Category entity) {
		id = entity.getId();
		name = entity.getName();
	}

}
