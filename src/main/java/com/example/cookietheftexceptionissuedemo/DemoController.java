package com.example.cookietheftexceptionissuedemo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Igor Rybak
 * @since 28-Oct-2018
 */
@RestController
public class DemoController {
    @GetMapping("/hello")
    public String getHello() {
        return "hello!";
    }
}
