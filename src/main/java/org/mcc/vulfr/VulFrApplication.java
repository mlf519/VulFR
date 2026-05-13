package org.mcc.vulfr;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class VulFrApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulFrApplication.class, args);
    }

}
