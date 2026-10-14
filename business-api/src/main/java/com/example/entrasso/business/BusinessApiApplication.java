package com.example.entrasso.business;

import com.example.entrasso.sso.EnableEntraSso;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Starts the business API, whose endpoints are protected by Entra roles. */
@SpringBootApplication
@EnableEntraSso
public class BusinessApiApplication {

  /** Launches the API and its embedded web server. */
  public static void main(String[] args) {
    SpringApplication.run(BusinessApiApplication.class, args);
  }
}
