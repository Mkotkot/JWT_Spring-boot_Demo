package com.kotkot.myDemo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;


@Controller
@RequestMapping("/api/admin/")
public class AdminController {
    static List<Student> admins;

    static {
        admins = new ArrayList<>();
        admins.add(new Student(1, "ADMIN Mohamed", "Tanta", "29384293462", 9000));
        admins.add(new Student(2, "ADMIN Ahmed", "Cairo", "293983423462", 5500));
        admins.add(new Student(3, "ADMIN Mina", "Suiz", "12312393462", 6000));
        admins.add(new Student(4, "ADMIN Yhia", "Siwa", "297897840462", 8000));
    }

    @GetMapping("/get")
    @ResponseBody
    @PreAuthorize("hasRole('ADMIN')")
    public String getAdminFunction() {
        return "Hello World Get Get Get Get  ADMIN ";
    }

    @PostMapping("/post")
    @ResponseBody
    @PreAuthorize("hasRole('ADMIN')")
    public String postAdminFunction() {
        return "Hello World POST POST POST POST  ADMIN ";
    }

    @PutMapping("/put")
    @ResponseBody
    @PreAuthorize("hasRole('ADMIN')")
    public String putAdminFunction() {
        return "Hello World PUT PUT PUT PUT  ADMIN ";
    }

    @DeleteMapping("/delete")
    @ResponseBody
    @PreAuthorize("hasRole('ADMIN')")
    public String deleteAdminFunction() {
        return "Hello World DELETE DELETE DELETE  ADMIN ";
    }

}
