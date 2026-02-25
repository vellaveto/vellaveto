package com.vellaveto;

/**
 * Base exception for Vellaveto SDK errors.
 */
public class VellavetoException extends Exception {

    private final int statusCode;

    public VellavetoException(String message) {
        super("vellaveto: " + message);
        this.statusCode = 0;
    }

    public VellavetoException(String message, int statusCode) {
        super("vellaveto: " + message + " (HTTP " + statusCode + ")");
        this.statusCode = statusCode;
    }

    public VellavetoException(String message, Throwable cause) {
        super("vellaveto: " + message, cause);
        this.statusCode = 0;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
