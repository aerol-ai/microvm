package ai.aerol.microvm.model;

/**
 * Options for {@code Sandbox.exposePort} / {@code MicroVMClient.exposePort}.
 * Defaults to {@link ExposeProtocol#HTTP} so a freshly-constructed instance
 * keeps the historical behavior.
 */
public class ExposeOptions {
    public ExposeProtocol protocol = ExposeProtocol.HTTP;
    /**
     * Who can open the URL: {@code "public"} or {@code "token"} (the URL then
     * needs a sandbox token for this port; HTTP ports on a server with a
     * domain only). {@code null} sends nothing: a new port is public and an
     * exposed port keeps what it has. Set it to change it.
     */
    public String visibility;

    public ExposeOptions setVisibility(String visibility) {
        this.visibility = visibility;
        return this;
    }

    /** An HTTP port whose URL needs a sandbox token. */
    public static ExposeOptions token() {
        return new ExposeOptions().setVisibility("token");
    }

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
