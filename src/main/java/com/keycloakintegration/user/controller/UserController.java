package com.keycloakintegration.user.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.service.annotation.PatchExchange;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/users")
@Slf4j
public class UserController {


    @PostMapping("/add")
    public Map<String, String> addUser(@RequestParam(value = "userName") String userName) {
        Map<String, String> response = new HashMap<>();
        response.put("Message", "User Added Successfully");
        response.put("Response", "200");
        return response;
    }

    @PatchMapping("/{userId}")
    public Map<String, String> updateUser(@PathVariable(value = "userId") String userId) {
        Map<String, String> response = new HashMap<>();
        response.put("Message", "User Updated Successfully");
        response.put("Response", "200");
        return response;
    }

    @DeleteMapping("/{userId}")
    public Map<String, String> deleteUser(@PathVariable(value = "userId") String userId) {
        Map<String, String> response = new HashMap<>();
        response.put("Message", "User Deleted Successfully");
        response.put("Response", "200");
        return response;
    }

    @GetMapping("/login")
    public Map<String, String> login(@RequestParam(value = "userId") String userId,
                                     @RequestParam(value = "password") String password) {
        Map<String, String> response = new HashMap<>();
        response.put("Message", "loggedIn successfully");
        response.put("Response", "200");
        return response;
    }
}
