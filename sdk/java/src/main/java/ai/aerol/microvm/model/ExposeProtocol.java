package ai.aerol.microvm.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Wire protocol an exposure publishes through. {@link #HTTP} is the
 * historical default ({@code https://<id>-<port>.<domain>}); {@link #TCP}
 * publishes via caddy-l4 to a parent-host port; {@link #TLS} multiplexes a
 * TLS-SNI route on the shared layer4 listener.
 */
public enum ExposeProtocol {
    HTTP("http"),
    TCP("tcp"),
    TLS("tls");

    private final String wireValue;

    ExposeProtocol(String wireValue) {
        this.wireValue = wireValue;
    }

    @JsonValue
    public String getWireValue() {
        return wireValue;
    }

    @JsonCreator
    public static ExposeProtocol fromWire(String value) {
        if (value == null) {
            return HTTP;
        }
        switch (value) {
            case "tcp":
                return TCP;
            case "tls":
                return TLS;
            case "http":
            case "":
                return HTTP;
            default:
                throw new IllegalArgumentException("unknown expose protocol: " + value);
        }
    }
}
