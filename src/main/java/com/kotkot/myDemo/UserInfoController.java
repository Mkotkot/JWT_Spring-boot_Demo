package com.kotkot.myDemo;

import com.kotkot.myDemo.auth.UserInfoService;
import com.kotkot.myDemo.model.UserInfo;
import com.kotkot.myDemo.repository.UserInfoRepository;
import com.kotkot.myDemo.security.ApplicationRoles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/start")
public class UserInfoController {

    private UserInfoService userInfoService;
    private UserInfoRepository userInfoRepository;
    private PasswordEncoder passwordEncoder;

    @Autowired
    public UserInfoController(UserInfoService userInfoService, UserInfoRepository userInfoRepository, PasswordEncoder passwordEncoder) {
        this.userInfoService = userInfoService;
        this.userInfoRepository = userInfoRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/insert1")
    @ResponseBody
    public String insert1() {
        UserInfo userInfo = new UserInfo();
        userInfo.setUserName("student");
        userInfo.setRole(ApplicationRoles.STUDENT.name());
        userInfo.setFullName("Full Name As student ");
        userInfo.setPassword(passwordEncoder.encode("password"));
        System.out.println(userInfo);
        System.out.println(userInfo);
        System.out.println(userInfo);
        System.out.println(userInfo);
        userInfoService.addUser(userInfo);
        return "Success Insert For \n" + userInfo;
    }

    @GetMapping("/insert2")
    @ResponseBody
    public String insert2() {
        UserInfo userInfo = new UserInfo();
        userInfo.setUserName("course");
        userInfo.setRole(ApplicationRoles.COURSE.name());
        userInfo.setFullName("Full Name As curse ");
        userInfo.setPassword(passwordEncoder.encode("password"));
        userInfoRepository.save(userInfo);
        return "Success Insert For \n" + userInfo;
    }

    @GetMapping("/insert3")
    @ResponseBody
    public String insert3() {
        UserInfo userInfo = new UserInfo();
        userInfo.setUserName("admin");
        userInfo.setRole(ApplicationRoles.ADMIN.name());
        userInfo.setFullName("Full Name As admin ");
        userInfo.setPassword(passwordEncoder.encode("password"));
        userInfoService.addUser(userInfo);
        return "Success Insert For \n" + userInfo;
    }

    @GetMapping("/all")
    @ResponseBody
    public String loadAll() {
        return userInfoService.loadAllUserData() + "";
    }

}
