package ai.aerol.microvm.model;

/**
 * {@code client.tokens().create()}'s result: the stored token plus
 * {@link #token}, the secret ({@code avm_…}), returned this once and never
 * stored by the server.
 */
public class CreatedApiToken extends ApiToken {
    public String token;
}
