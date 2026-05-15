package ai.aerol.microvm.model;

/**
 * Optional knobs for {@code MicroVMClient.buildImage(Image, BuildImageOptions)}.
 */
public class BuildImageOptions {
    /** Optional push directive — when set, the built image is pushed after the build succeeds. */
    public BuildImagePushOptions push;

    /**
     * Sets the push directive applied after a successful build.
     *
     * @param push push options, or {@code null} to skip pushing.
     * @return this options instance for chaining.
     */
    public BuildImageOptions setPush(BuildImagePushOptions push) {
        this.push = push;
        return this;
    }
}
