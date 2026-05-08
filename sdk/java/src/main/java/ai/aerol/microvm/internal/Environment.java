package ai.aerol.microvm.internal;

@FunctionalInterface
public interface Environment {
    String get(String name);
}