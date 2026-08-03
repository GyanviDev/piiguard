package com.piiguard.piiguard.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.web.config.EnableSpringDataWebSupport;

/**
 * Web-layer configuration.
 *
 * <p>Spring Data warns at startup that serialising a {@code PageImpl} directly gives no
 * stability guarantee about the resulting JSON — the internal shape of that class is free to
 * change between versions, which would silently break every client of {@code /api/audit} on a
 * dependency upgrade. {@code VIA_DTO} serialises through a stable, documented wrapper instead,
 * so the pagination contract is ours rather than an implementation detail that happens to be
 * observable.
 *
 * <p>Worth fixing rather than muting: a startup warning that is ignored for long enough stops
 * being read, and then the next one is ignored too.
 */
@Configuration
@EnableSpringDataWebSupport(pageSerializationMode = EnableSpringDataWebSupport.PageSerializationMode.VIA_DTO)
public class WebConfig {
}
