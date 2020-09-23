package com.kotkot.myDemo;

import lombok.Data;


@Data
public class Student {


    private int id;
    private String name;
    private String address;
    private String mobile;
    private double salary;

    public Student(int id, String name, String address, String mobile, double salary) {
        this.id = id;
        this.name = name;
        this.address = address;
        this.mobile = mobile;
        this.salary = salary;

    }


}
