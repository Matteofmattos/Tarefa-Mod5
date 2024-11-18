package com.Matteof.mattos.DsEcommerce_Oauth2.service;

import com.Matteof.mattos.DsEcommerce_Oauth2.Projections.UserDetailsProjection;
import com.Matteof.mattos.DsEcommerce_Oauth2.Repository.UserRepository;
import com.Matteof.mattos.DsEcommerce_Oauth2.entities.Role;
import com.Matteof.mattos.DsEcommerce_Oauth2.entities.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        List<UserDetailsProjection> result = repository.searchUserAndRolesByEmail(username);

        if (result.isEmpty()) throw new UsernameNotFoundException("Email not found");

        User user = new User();

        user.setEmail(result.getFirst().getUsername());
        user.setPassword(result.getFirst().getPassword());
        for (UserDetailsProjection projection : result) {
            user.addRole(new Role(projection.getRoleId(), projection.getAuthority()));
        }

        return user;
    }
}
