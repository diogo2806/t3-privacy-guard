package br.com.privacyguard.runtime.policy;

public record AppliedPolicy(PolicyDocument document, String version, String hash) {}
