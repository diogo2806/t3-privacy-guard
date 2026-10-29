-- Baseline schema for PostgreSQL, generated from the JPA entities (Hibernate PostgreSQLDialect).
-- Later changes go in new V<n>__<description>.sql files; never edit a migration that has been applied.

create table action_proposals (
    created_at timestamp(6) with time zone not null,
    remediation_authorized_at timestamp(6) with time zone,
    incident_id varchar(36) not null,
    status varchar(40) not null check (status in ('PENDING','EVALUATED','REMEDIATION_AUTHORIZED','REMEDIATED')),
    action varchar(80) not null,
    purpose varchar(80) not null,
    request_id varchar(128) not null,
    remediation_authorized_by varchar(160),
    resource varchar(240) not null,
    host varchar(253),
    private_refs_json varchar(1000) not null,
    fields_json varchar(4000) not null,
    normal_payload_json varchar(8000),
    id varchar(255) not null,
    primary key (id),
    constraint uk_action_request_id unique (request_id)
);

create table audit_chain_heads (
    last_sequence bigint not null,
    legacy_event_count bigint not null,
    updated_at timestamp(6) with time zone not null,
    integrity_version varchar(16) not null,
    integrity_key_id varchar(32) not null,
    incident_id varchar(36) not null,
    head_mac varchar(64) not null,
    last_event_mac varchar(64) not null,
    primary key (incident_id)
);

create table audit_events (
    created_at timestamp(6) with time zone not null,
    sequence_number bigint,
    t3n_sequence bigint,
    integrity_version varchar(16),
    integrity_key_id varchar(32),
    incident_id varchar(36) not null,
    event_mac varchar(64),
    previous_mac varchar(64),
    type varchar(64) not null,
    t3n_function varchar(120),
    t3n_hash varchar(128),
    message varchar(600) not null,
    id varchar(255) not null,
    primary key (id)
);

create table execution_trace_events (
    created_at timestamp(6) with time zone not null,
    duration_ms bigint,
    state varchar(32) not null,
    action_id varchar(36) not null,
    id varchar(36) not null,
    incident_id varchar(36) not null,
    stage varchar(64) not null,
    trace_id varchar(64) not null,
    reason_code varchar(80),
    request_id varchar(128) not null,
    primary key (id)
);

create table incidents (
    created_at timestamp(6) with time zone not null,
    expires_at timestamp(6) with time zone,
    severity varchar(16) not null check (severity in ('LOW','MEDIUM','HIGH','CRITICAL')),
    origin_type varchar(24) check (origin_type in ('APPLICATION','EXTERNAL')),
    status varchar(32) not null,
    integration_id varchar(64),
    source varchar(120) not null,
    external_event_id varchar(128),
    title varchar(160) not null,
    summary varchar(2000) not null,
    id varchar(255) not null,
    primary key (id),
    constraint uk_incident_integration_external_event unique (integration_id, external_event_id)
);

create table policy_decisions (
    requires_human_authorization boolean,
    evaluated_at timestamp(6) with time zone not null,
    decision varchar(12) not null check (decision in ('ALLOW','REDACT','DENY')),
    action_proposal_id varchar(36) not null,
    policy_hash varchar(64),
    policy_version varchar(64),
    reason_code varchar(80) not null,
    reason varchar(800) not null,
    allowed_private_refs_json varchar(1000) not null,
    redacted_private_refs_json varchar(1000) not null,
    allowed_fields_json varchar(4000) not null,
    redacted_fields_json varchar(4000) not null,
    id varchar(255) not null,
    primary key (id),
    constraint uk_decision_action unique (action_proposal_id)
);

create table remediation_executions (
    http_code integer,
    verification_attempts integer not null,
    completed_at timestamp(6) with time zone,
    last_attempt_at timestamp(6) with time zone not null,
    started_at timestamp(6) with time zone not null,
    version bigint not null,
    status varchar(32) not null check (status in ('EXECUTING','PENDING_VERIFICATION','COMPLETED','UNVERIFIED','FAILED')),
    action_proposal_id varchar(36) not null,
    failure_code varchar(120),
    request_id varchar(128) not null,
    execution_principal varchar(160),
    operation_id varchar(200),
    id varchar(255) not null,
    primary key (id),
    constraint uk_remediation_action unique (action_proposal_id)
);

create table security_remediation_operations (
    must_egress_seen boolean not null,
    must_not_egress_seen boolean not null,
    recipient_resolved boolean not null,
    created_at timestamp(6) with time zone not null,
    updated_at timestamp(6) with time zone not null,
    action varchar(32) not null,
    state varchar(32) not null,
    operation_id varchar(80) not null,
    request_id varchar(128) not null,
    primary key (operation_id),
    constraint uk_security_remediation_request unique (request_id)
);

create index idx_trace_incident_action_time 
   on execution_trace_events (incident_id, action_id, created_at);
