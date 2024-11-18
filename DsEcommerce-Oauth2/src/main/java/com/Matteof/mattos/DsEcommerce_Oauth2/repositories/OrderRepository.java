package com.Matteof.mattos.DsEcommerce_Oauth2.repositories;


import com.Matteof.mattos.DsEcommerce_Oauth2.entities.Order;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OrderRepository extends JpaRepository<Order, Long> {
}
