package com.piiguard.piiguard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Entry point for the PII Guard privacy proxy.
 *
 * <p>{@code @EnableScheduling} powers two background jobs that are load-bearing for privacy
 * rather than cosmetic: the token vault sweeper (destroys plaintext PII left by abandoned
 * sessions) and the audit retention job (enforces the storage limitation principle).
 *
 * <p>{@link UserDetailsServiceAutoConfiguration} is excluded deliberately. Left enabled, Spring
 * Boot creates a default {@code user} account with a random password printed to the console at
 * every startup. Nothing in this application authenticates against it — admin access is a shared
 * secret header — so it is an unused credential that exists only to be misconfigured into
 * usefulness later, and a warning in the log that trains everyone to ignore warnings in the log.
 */
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
@ConfigurationPropertiesScan
@EnableScheduling
public class PiiguardApplication {

	public static void main(String[] args) {
		SpringApplication.run(PiiguardApplication.class, args);
	}
}
