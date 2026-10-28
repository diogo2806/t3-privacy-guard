package br.com.privacyguard.runtime.contract;

/**
 * The contract refused to act (the Rust functions' Err(String)). Messages are the contract's own and never carry
 * secrets or private values, so they can be returned to the authenticated caller, as T3N did.
 */
public class ContractRejectedException extends RuntimeException {
    public ContractRejectedException(String message) {
        super(message);
    }
}
