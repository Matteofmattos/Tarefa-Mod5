package com.Matteof.mattos.DsEcommerce_Oauth2.Projections;

public interface UserDetailsProjection {

    String getUsername();
    String getPassword();
    Long getRoleId();
    String getAuthority();
}

