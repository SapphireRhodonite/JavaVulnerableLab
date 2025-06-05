package org.cysecurity.cspf.jvl;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;

@SpringBootApplication
@ServletComponentScan
public class JavaVulnerableLabApplication {
    public static void main(String[] args) {
        SpringApplication.run(JavaVulnerableLabApplication.class, args);
    }
}
