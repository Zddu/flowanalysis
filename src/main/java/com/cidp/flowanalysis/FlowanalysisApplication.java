package com.cidp.flowanalysis;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@MapperScan("com.cidp.flowanalysis.mapper")
@EnableAsync
@EnableScheduling
public class FlowanalysisApplication {

    public static void main(String[] args) {
        SpringApplication.run(FlowanalysisApplication.class, args);
    }

}
