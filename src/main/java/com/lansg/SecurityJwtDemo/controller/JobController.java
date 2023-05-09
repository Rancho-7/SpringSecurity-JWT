package com.lansg.SecurityJwtDemo.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/jobs")
public class JobController {

    @GetMapping("/list")
    public String listJobs(){
        System.out.println("接收到请求...");
        return "展示所有任务";
    }

    //通过PermissionService自定义授权实现
    @PostMapping("/create")
    @PreAuthorize("@ss.hasPer('job:add')")
    public String createJob(){
        return "创建一个新任务";
    }

    //通过SpringSecurity配合用户角色(role字段)实现权限管理
    @DeleteMapping("/delete")
    public String deleteJob(){
        return "删除一个任务";
    }
}
