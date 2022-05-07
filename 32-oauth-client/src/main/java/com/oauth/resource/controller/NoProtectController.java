package com.oauth.resource.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @Author xry
 * @Date 2021/12/27 16:05
 */
@RestController
public class NoProtectController {
    @RequestMapping("/no/protect")
    public Map<String,String> test(){
        HashMap<String, String> map = new HashMap<>();
        map.put("no-protect","protect11");
        return map;
    }
}
