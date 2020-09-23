package com.kotkot.myDemo.model;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Data
public class UserInfoDetails implements UserDetails {

    private final Collection<? extends GrantedAuthority> grantedAuthority;
    private final String password;
    private final String username;
    private final String fullName;

    public UserInfoDetails(Collection<? extends GrantedAuthority> grantedAuthority, String password, String username, String fullName) {
        this.grantedAuthority = grantedAuthority;
        this.password = password;
        this.username = username;
        this.fullName = fullName;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.grantedAuthority;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
