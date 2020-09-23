package com.kotkot.myDemo.model;

import javax.persistence.*;

@Entity
@Table(name = "tea_user", schema = "teacher_db", catalog = "")
public class TeaUser {
    private String userName;
    private String role;
    private String fullName;
    private String password;
    private int userId;

    @Basic
    @Column(name = "userName", nullable = false, length = 100)
    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    @Basic
    @Column(name = "role", nullable = true, length = 100)
    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    @Basic
    @Column(name = "full_name", nullable = true, length = 400)
    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    @Basic
    @Column(name = "password", nullable = true, length = 200)
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Id
    @Column(name = "userId", nullable = false)
    public int getUserId() {
        return userId;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TeaUser teaUser = (TeaUser) o;

        if (userId != teaUser.userId) return false;
        if (userName != null ? !userName.equals(teaUser.userName) : teaUser.userName != null) return false;
        if (role != null ? !role.equals(teaUser.role) : teaUser.role != null) return false;
        if (fullName != null ? !fullName.equals(teaUser.fullName) : teaUser.fullName != null) return false;
        if (password != null ? !password.equals(teaUser.password) : teaUser.password != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = userName != null ? userName.hashCode() : 0;
        result = 31 * result + (role != null ? role.hashCode() : 0);
        result = 31 * result + (fullName != null ? fullName.hashCode() : 0);
        result = 31 * result + (password != null ? password.hashCode() : 0);
        result = 31 * result + userId;
        return result;
    }
}
