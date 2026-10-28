package br.com.privacyguard.runtime.contract;

public class InvalidContractInputException extends RuntimeException {
    public InvalidContractInputException(String message) {
        super(message);
    }
}
