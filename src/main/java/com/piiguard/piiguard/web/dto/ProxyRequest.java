package com.piiguard.piiguard.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * The request body for {@code POST /api/proxy}.
 *
 * <p>The endpoint previously accepted {@code Map<String, String>} and validated it with two
 * hand-written {@code if} blocks in the controller. A typed, validated DTO is better on three
 * counts that all matter here:
 *
 * <ul>
 *   <li>Validation runs before the controller method is entered, so the checks cannot be
 *       skipped by a new code path that forgets to call them — and the length bound in
 *       particular is a denial-of-service control, since prompt length drives regex work,
 *       model inference cost and upstream spend.</li>
 *   <li>An untyped map silently accepts any field a caller invents, which makes the contract
 *       whatever the implementation happens to read today.</li>
 *   <li>The shape is discoverable from the type instead of from reading the method body.</li>
 * </ul>
 *
 * @param prompt      the user's text, pre-redaction
 * @param applyNoise  opt out of numeric perturbation for prompts where exact figures matter.
 *                    Making this a per-request choice acknowledges that noise is a genuine
 *                    trade against answer quality rather than a free improvement.
 */
public record ProxyRequest(

        @NotBlank(message = "Prompt cannot be empty")
        @Size(max = 10_000, message = "Prompt exceeds the maximum length of 10,000 characters")
        String prompt,

        Boolean applyNoise) {

    public boolean noiseRequested() {
        return applyNoise == null || applyNoise;
    }
}
