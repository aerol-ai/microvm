package ai.aerol.microvm.internal.api.v1;

/**
 * v1 path-prefix constant for the Java SDK.
 *
 * <p>Mirrors the prefix exported by {@code pkg/api/v1/dto.go::PathPrefix} on
 * the server. When v2 lands, a sibling
 * {@code ai.aerol.microvm.internal.api.v2.Paths} will export its own
 * {@code PATH_PREFIX}, and {@code MicroVMConfig.apiVersion} selects which one
 * to use.
 */
public final class Paths {
    public static final String PATH_PREFIX = "/v1";

    private Paths() {}
}
