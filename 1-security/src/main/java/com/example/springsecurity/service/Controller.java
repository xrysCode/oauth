package com.example.springsecurity.service;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @Author xry
 * @Date 2022/4/24 16:34
 */
@RestController
public class Controller {
    @RequestMapping("home")
    public Map<String,String> a(){
        HashMap<String, String> map = new HashMap<>();
        return map;
    }
}
