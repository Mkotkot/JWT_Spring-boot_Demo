package com.kotkot.myDemo.repository;

import com.kotkot.myDemo.model.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserInfoRepository extends JpaRepository<UserInfo, Integer> {

    UserInfo getUserInfoByUserName(String userName);

}
