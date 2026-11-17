package com.deepcyber.training;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class TrainingLabApplication {

    private static final Logger log = LoggerFactory.getLogger(TrainingLabApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(TrainingLabApplication.class, args);
    }

    @Bean
    CommandLineRunner trainingOnlyWarning() {
        return args -> log.warn("TRAINING ONLY: this application is deliberately vulnerable and must never be exposed to untrusted networks");
    }
}
