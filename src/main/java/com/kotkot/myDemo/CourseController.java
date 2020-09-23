package com.kotkot.myDemo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;


@Controller
@RequestMapping("/api/course/")
public class CourseController {
    static List<Student> coursesList;

    static {
        coursesList = new ArrayList<>();
        coursesList.add(new Student(1, "COURSE .. hamed", "Tanta", "29384293462", 9000));
        coursesList.add(new Student(2, "COURSE .. med", "Cairo", "293983423462", 5500));
        coursesList.add(new Student(3, "COURSE .. na", "Suiz", "12312393462", 6000));
        coursesList.add(new Student(4, "COURSE .. ia", "Siwa", "297897840462", 8000));
    }

    @GetMapping("/get")
    @ResponseBody
    @PreAuthorize("hasRole('COURSE')")
    public String getCourseFunction() {
        return "Hello World Get Get Get Get  COURSE ";
    }

    @RequestMapping(value = "/csrf-token", method = RequestMethod.GET)
    public @ResponseBody
    String getCsrfToken(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        System.out.println(token.getHeaderName());
        System.out.println(token.getToken());
        return token.getToken();
    }

    @PostMapping("/post")
    @ResponseBody
    @PreAuthorize("hasRole('COURSE')")
    public String postCourseFunction() {
        return "Hello World POST POST POST POST  COURSE ";
    }

    @PutMapping("/put")
    @ResponseBody
    @PreAuthorize("hasRole('COURSE')")
    public String putCourseFunction() {
        return "Hello World PUT PUT PUT PUT  COURSE ";
    }

    @DeleteMapping("/delete")
    @ResponseBody
    @PreAuthorize("hasRole('COURSE')")
    public String deleteCourseFunction() {
        return "Hello World DELETE DELETE DELETE  COURSE ";
    }
}

