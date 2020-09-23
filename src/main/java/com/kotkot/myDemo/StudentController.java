package com.kotkot.myDemo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/api/student/")
public class StudentController {
    static List<Student> students;

    static {
        students = new ArrayList<>();
        students.add(new Student(1, "Mohamed", "Tanta", "29384293462", 9000));
        students.add(new Student(2, "Ahmed", "Cairo", "293983423462", 5500));
        students.add(new Student(3, "Mina", "Suiz", "12312393462", 6000));
        students.add(new Student(4, "Yehia", "Siwa", "297897840462", 8000));
    }

    @GetMapping("/{id}")
    @ResponseBody
    public Student getStudenetObject(@PathVariable("id") int id) {
        return students.get(id - 1);
    }

    @GetMapping("/")
    @ResponseBody
    public String getHomeText() {
        return "Hello World Home Page ";
    }

    @GetMapping("/get")
    @ResponseBody
    @PreAuthorize("hasRole('STUDENT')")
    public String getStudentFunction() {
        return "Hello World Get Get Get Get  STUDENT ";
    }

    @PostMapping("/post")
    @ResponseBody
    @PreAuthorize("hasRole('STUDENT')")
    public String postStudentFunction() {

        System.out.println("...");
        return "Hello World POST POST POST POST  STUDENT ";
    }

    @PutMapping("/put")
    @ResponseBody
    @PreAuthorize("hasRole('STUDENT')")
    public String putStudentFunction() {
        return "Hello World PUT PUT PUT PUT  STUDENT ";
    }

    @DeleteMapping("/delete")
    @ResponseBody
    @PreAuthorize("hasRole('STUDENT')")
    public String deleteStudentFunction() {
        return "Hello World DELETE DELETE DELETE  STUDENT ";
    }

}
