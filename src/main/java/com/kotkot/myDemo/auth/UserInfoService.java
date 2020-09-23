package com.kotkot.myDemo.auth;

import com.kotkot.myDemo.model.UserInfo;
import com.kotkot.myDemo.model.UserInfoDetails;

import java.util.List;

public interface UserInfoService {
    List<UserInfo> loadAllUserData();

    UserInfoDetails convertToUserDetails(UserInfo userInfo);

    void addUser(UserInfo userInfo);
}
