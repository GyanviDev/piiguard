package com.piiguard.piiguard.audit;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    /**
     * The controller previously called {@code findAll()} and serialised the entire table into
     * one response. That is an unbounded query against a table that grows with every request:
     * fine on day one, an out-of-memory error and a multi-megabyte response by the time the
     * data is interesting enough to want. Pagination is not a nicety on an audit log.
     */
    Page<AuditLog> findAllByOrderByCreatedAtDesc(Pageable pageable);

    Page<AuditLog> findByAttackDetectedTrueOrderByCreatedAtDesc(Pageable pageable);

    long countByAttackDetectedTrue();

    /** Enforces the configured retention period. */
    @Modifying
    @Query("delete from AuditLog a where a.createdAt < :cutoff")
    int deleteOlderThan(@Param("cutoff") Instant cutoff);
}
