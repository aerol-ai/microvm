package ai.aerol.microvm;

public class MicroVMException extends RuntimeException {
    public MicroVMException(String message) {
        super(message);
    }

    public MicroVMException(String message, Throwable cause) {
        super(message, cause);
    }
}