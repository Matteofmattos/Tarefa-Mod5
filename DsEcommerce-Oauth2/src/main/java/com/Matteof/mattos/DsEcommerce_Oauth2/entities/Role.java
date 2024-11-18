package com.Matteof.mattos.DsEcommerce_Oauth2.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import java.util.Objects;

@SuppressWarnings("serial")
@Entity
@Getter
@Setter
@Table(name = "tb_role")
public class Role implements GrantedAuthority {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	private String authority;

	public Role() {
	}

	public Role(Long id, String authority) {
		this.id = id;
		this.authority = authority;
	}

	@Override
	public String getAuthority() {
		return authority;
	}

	@Override
	public int hashCode() {
		return Objects.hash(authority);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Role other = (Role) obj;
		return Objects.equals(authority, other.authority);
	}
}
