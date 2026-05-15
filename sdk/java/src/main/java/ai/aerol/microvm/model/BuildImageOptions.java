package ai.aerol.microvm.model;

/**
 * Optional knobs for {@code MicroVMClient.buildImage(Image, BuildImageOptions)}.
 */
public class BuildImageOptions {
    public BuildImagePushOptions push;

    public BuildImageOptions setPush(BuildImagePushOptions push) {
        this.push = push;
        return this;
    }
}
