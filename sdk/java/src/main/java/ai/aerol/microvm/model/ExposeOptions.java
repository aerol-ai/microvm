package ai.aerol.microvm.model;

/**
 * Options for {@code Sandbox.exposePort} / {@code MicroVMClient.exposePort}.
 * Defaults to {@link ExposeProtocol#HTTP} so a freshly-constructed instance
 * keeps the historical behavior.
 */
public class ExposeOptions {
    public ExposeProtocol protocol = ExposeProtocol.HTTP;

    public ExposeOptions setProtocol(ExposeProtocol protocol) {
        this.protocol = protocol == null ? ExposeProtocol.HTTP : protocol;
        return this;
    }

    public static ExposeOptions http() {
        return new ExposeOptions().setProtocol(ExposeProtocol.HTTP);
    }

    public static ExposeOptions tcp() {
        return new ExposeOptions().setProtocol(ExposeProtocol.TCP);
    }

    public static ExposeOptions tls() {
        return new ExposeOptions().setProtocol(ExposeProtocol.TLS);
    }
}
