package ai.aerol.microvm.model;

/**
 * Response from {@code MicroVMClient.buildImage(Image, BuildImageOptions)}.
 */
public class BuildImageResult {
    /** Local content-addressed tag (always returned). */
    public final String image;
    /** Pushed reference (e.g. {@code "ghcr.io/x/y:v1"}) when push was requested, otherwise null. */
    public final String pushed;

    public BuildImageResult(String image, String pushed) {
        this.image = image;
        this.pushed = pushed;
    }
}
