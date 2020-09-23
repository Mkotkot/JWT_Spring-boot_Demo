package com.kotkot.myDemo.auth;

import com.kotkot.myDemo.model.UserInfo;
import com.kotkot.myDemo.model.UserInfoDetails;
import com.kotkot.myDemo.repository.UserInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserInfoServiceImpl implements UserInfoService, UserDetailsService {
    private final PasswordEncoder passwordEncoder;
    private final UserInfoRepository userInfoRepository;

    @Autowired
    public UserInfoServiceImpl(PasswordEncoder passwordEncoder, UserInfoRepository userInfoRepository) {
        this.passwordEncoder = passwordEncoder;
        this.userInfoRepository = userInfoRepository;
    }

    @Override
    public List<UserInfo> loadAllUserData() {
        return userInfoRepository.findAll();
    }

    @Override
    public UserInfoDetails convertToUserDetails(UserInfo userInfo) {
        return new UserInfoDetails(roles(userInfo.getRole()), userInfo.getPassword(), userInfo.getUserName(), userInfo.getFullName());
    }

    @Override
    public void addUser(UserInfo userInfo) {
        userInfoRepository.save(userInfo);
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        System.out.println(s);
        System.out.println(s);
        System.out.println(s);
        System.out.println(s);
        UserInfo userInfo = userInfoRepository.getUserInfoByUserName(s);
        if (userInfo == null) {
            throw new UsernameNotFoundException("User not authorized.");
        }
        return convertToUserDetails(userInfo);
    }

    private List<GrantedAuthority> roles(String role) {
        List<GrantedAuthority> authorities = new ArrayList();
        if (role.startsWith("ROLE_")) {
            System.out.println(role + " cannot start with ROLE_ (it is automatically added)");
        } else {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
        }
        return authorities;
    }
}
