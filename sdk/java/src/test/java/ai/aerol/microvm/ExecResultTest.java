package ai.aerol.microvm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ai.aerol.microvm.model.ExecResult;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class ExecResultTest {
    private final ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    @Test
    void timedOutDefaultsToFalseForOlderAgents() throws Exception {
        ExecResult result = mapper.readValue("{\"stdout\":\"\",\"stderr\":\"\",\"exit_code\":0,\"duration_ms\":1}", ExecResult.class);
        assertFalse(result.timedOut);
    }

    @Test
    void timedOutIsRead() throws Exception {
        ExecResult result = mapper.readValue("{\"stdout\":\"\",\"stderr\":\"\",\"exit_code\":-1,\"duration_ms\":1000,\"timed_out\":true}", ExecResult.class);
        assertTrue(result.timedOut);
        assertEquals(-1, result.exitCode);
    }

    @Test
    void signalIsReadAndNullForOlderAgents() throws Exception {
        ExecResult killed = mapper.readValue("{\"stdout\":\"\",\"stderr\":\"\",\"exit_code\":-1,\"duration_ms\":1000,\"timed_out\":true,\"signal\":\"SIGKILL\"}", ExecResult.class);
        assertEquals("SIGKILL", killed.signal);
        assertEquals(-1, killed.exitCode);
        ExecResult older = mapper.readValue("{\"stdout\":\"\",\"stderr\":\"\",\"exit_code\":0,\"duration_ms\":1}", ExecResult.class);
        assertEquals(null, older.signal);
    }
}
