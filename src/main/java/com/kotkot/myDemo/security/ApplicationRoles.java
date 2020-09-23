package com.kotkot.myDemo.security;

public enum ApplicationRoles {
    ADMIN("ADMIN"),
    STUDENT("STUDENT"),
    COURSE("COURSE");

//    ADMIN(new HashSet<>(Arrays.asList(ApplicationRolePermissions.COURSE_WRITE, ApplicationRolePermissions.COURSE_READ,
//            ApplicationRolePermissions.STUDENT_WRITE, ApplicationRolePermissions.STUDENT_READ))),
//    STUDENT(new HashSet<>(Arrays.asList(ApplicationRolePermissions.STUDENT_WRITE, ApplicationRolePermissions.STUDENT_READ))),
//    COURSE(new HashSet<>(Arrays.asList(ApplicationRolePermissions.COURSE_WRITE, ApplicationRolePermissions.STUDENT_READ)));


    private String role;
//    private Set<ApplicationRolePermissions> rolePermissions;


    ApplicationRoles(String role) {
        this.role = role;
    }


//    ApplicationRoles(Set<ApplicationRolePermissions> rolePermissions) {
//        this.rolePermissions = rolePermissions;
//    }


//    public Set<ApplicationRolePermissions> getPermissions() {
//        return this.rolePermissions;
//    }

//    public Set<SimpleGrantedAuthority> grantedAuthorities() {
//        Set<SimpleGrantedAuthority> permissionList = getPermissions().stream().map(
//                permission -> new SimpleGrantedAuthority(permission.getPermission())).collect(Collectors.toSet());
//        permissionList.add(new SimpleGrantedAuthority(this.name()));
//
//        return permissionList;
//    }

}
