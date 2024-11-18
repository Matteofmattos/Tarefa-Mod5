package com.Matteof.mattos.DsEcommerce_Oauth2.dto;

import com.Matteof.mattos.DsEcommerce_Oauth2.entities.OrderItem;
import lombok.Getter;

@Getter
public class OrderItemDTO {

	private Long productId;
	private String name;
	private Double price;
	private Integer quantity;
	private String imgUrl;
	
	public OrderItemDTO(Long productId, String name, Double price, Integer quantity, String imgUrl) {
		this.productId = productId;
		this.name = name;
		this.price = price;
		this.quantity = quantity;
		this.imgUrl = imgUrl;
	}
	
	public OrderItemDTO(OrderItem entity) {
		productId = entity.getProduct().getId();
		name = entity.getProduct().getName();
		price = entity.getPrice();
		quantity = entity.getQuantity();
		imgUrl = entity.getProduct().getImgUrl();
	}

    public Double getSubTotal() {
		return price * quantity;
	}

}
