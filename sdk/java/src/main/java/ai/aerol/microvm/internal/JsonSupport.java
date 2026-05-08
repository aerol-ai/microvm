package ai.aerol.microvm.internal;

import java.io.IOException;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import ai.aerol.microvm.MicroVMException;

public final class JsonSupport {
    private static final ObjectMapper MAPPER = buildMapper();

    private JsonSupport() {
    }

    public static String write(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException ex) {
            throw new MicroVMException("failed to encode JSON", ex);
        }
    }

    public static byte[] writeBytes(Object value) {
        try {
            return MAPPER.writeValueAsBytes(value);
        } catch (JsonProcessingException ex) {
            throw new MicroVMException("failed to encode JSON", ex);
        }
    }

    public static <T> T read(byte[] value, Class<T> type) {
        try {
            return MAPPER.readValue(value, type);
        } catch (IOException ex) {
            throw new MicroVMException("failed to decode JSON", ex);
        }
    }

    public static <T> T tryRead(byte[] value, Class<T> type) {
        try {
            return MAPPER.readValue(value, type);
        } catch (IOException ex) {
            return null;
        }
    }

    private static ObjectMapper buildMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        mapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        mapper.registerModule(new JavaTimeModule());
        return mapper;
    }
}