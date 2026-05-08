package ai.aerol.microvm.internal;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public final class StreamControlMessage {
    public String type;
    public Integer cols;
    public Integer rows;
    public String signal;

    public static StreamControlMessage resize(int cols, int rows) {
        StreamControlMessage message = new StreamControlMessage();
        message.type = "resize";
        message.cols = cols;
        message.rows = rows;
        return message;
    }

    public static StreamControlMessage signal(String signal) {
        StreamControlMessage message = new StreamControlMessage();
        message.type = "signal";
        message.signal = signal;
        return message;
    }

    public static StreamControlMessage close() {
        StreamControlMessage message = new StreamControlMessage();
        message.type = "close";
        return message;
    }
}