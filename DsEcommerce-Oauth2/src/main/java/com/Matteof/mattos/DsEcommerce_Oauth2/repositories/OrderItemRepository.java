package com.Matteof.mattos.DsEcommerce_Oauth2.repositories;

import com.Matteof.mattos.DsEcommerce_Oauth2.entities.OrderItem;
import com.Matteof.mattos.DsEcommerce_Oauth2.entities.OrderItemPK;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OrderItemRepository extends JpaRepository<OrderItem, OrderItemPK> {

}
