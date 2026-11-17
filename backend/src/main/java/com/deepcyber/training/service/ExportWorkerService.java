package com.deepcyber.training.service;

import com.deepcyber.training.api.LabApiException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Set;

/** Bounded, nonblocking bridge to the network-isolated worker. This JVM NEVER executes a shell. */
@Service
public class ExportWorkerService {
    private static final int MAX_FRAME = 65536;
    private final String socketPath;
    private final Duration deadline;
    private final ObjectMapper json = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

    @Autowired
    public ExportWorkerService(@Value("${lab.export-socket:/run/northstar-export/export.sock}") String socketPath) {
        this(socketPath, Duration.ofSeconds(4));
    }

    // Package-private constructor allows fast, deterministic deadline tests without a running container.
    ExportWorkerService(String socketPath, Duration deadline) {
        this.socketPath = socketPath;
        this.deadline = deadline;
    }

    public ExportResult export(String orderId, String format, boolean vulnerable) {
        validateFormat(format, vulnerable);
        // Do not send tokens, tenant details, notes, prices, signing keys or real business data.
        // The worker deliberately exports a fixed synthetic fixture, not interpolated order content.
        return exchange(Map.of("version", 1, "action", "export", "format", format,
                "vulnerable", vulnerable, "order", Map.of("id", orderId)));
    }

    /** Call only from trusted management/reset code, never an ordinary persona endpoint. */
    public ExportResult reset() {
        return exchange(Map.of("version", 1, "action", "reset"));
    }

    private static void validateFormat(String format, boolean vulnerable) {
        if (format == null || format.isEmpty() || format.length() > 128
                || format.chars().anyMatch(c -> c < 32 || c == 127)) {
            throw new LabApiException(HttpStatus.BAD_REQUEST, "INVALID_EXPORT_FORMAT", "Format must be 1–128 printable characters");
        }
        if (!vulnerable && !Set.of("csv", "json").contains(format)) {
            throw new LabApiException(HttpStatus.BAD_REQUEST, "INVALID_EXPORT_FORMAT", "Supported export formats are csv and json");
        }
    }

    private ExportResult exchange(Map<String, Object> request) {
        try (SocketChannel socket = SocketChannel.open(StandardProtocolFamily.UNIX);
             Selector selector = Selector.open()) {
            long expires = System.nanoTime() + deadline.toNanos();
            byte[] frame = (json.writeValueAsString(request) + "\n").getBytes(StandardCharsets.UTF_8);
            if (frame.length > MAX_FRAME) throw new IOException("Request exceeds frame limit");
            socket.configureBlocking(false);
            SelectionKey key = socket.register(selector, SelectionKey.OP_CONNECT);
            if (!socket.connect(UnixDomainSocketAddress.of(socketPath))) {
                while (!socket.finishConnect()) await(selector, key, SelectionKey.OP_CONNECT, expires);
            }
            ByteBuffer outgoing = ByteBuffer.wrap(frame);
            while (outgoing.hasRemaining()) {
                checkDeadline(expires);
                if (socket.write(outgoing) == 0) await(selector, key, SelectionKey.OP_WRITE, expires);
            }
            ByteArrayOutputStream incoming = new ByteArrayOutputStream();
            ByteBuffer buffer = ByteBuffer.allocate(4096);
            while (true) {
                checkDeadline(expires);
                int count = socket.read(buffer);
                if (count < 0) throw new IOException("Truncated worker response");
                if (count == 0) { await(selector, key, SelectionKey.OP_READ, expires); continue; }
                buffer.flip();
                while (buffer.hasRemaining()) {
                    byte next = buffer.get();
                    if (next == '\n') {
                        if (buffer.hasRemaining()) throw new IOException("Unexpected second worker frame");
                        return decode(incoming.toByteArray());
                    }
                    incoming.write(next);
                    if (incoming.size() >= MAX_FRAME) throw new IOException("Worker response exceeds frame limit");
                }
                buffer.clear();
            }
        } catch (IOException | IllegalArgumentException | UnsupportedOperationException error) {
            // Do not leak socket paths or transport internals to the application user.
            throw new LabApiException(HttpStatus.SERVICE_UNAVAILABLE, "EXPORT_WORKER_UNAVAILABLE",
                    "The isolated export worker is unavailable; no export was run in the application service");
        }
    }

    private ExportResult decode(byte[] bytes) throws IOException {
        JsonNode root;
        try (var parser = json.createParser(bytes)) {
            root = json.readTree(parser);
            if (parser.nextToken() != null) throw new IOException("Trailing worker JSON");
        }
        if (root == null || !root.isObject() || !root.path("output").isTextual()
                || root.path("output").asText().getBytes(StandardCharsets.UTF_8).length > 24576
                || !root.path("exitCode").isIntegralNumber() || !root.path("exitCode").canConvertToInt()
                || root.path("exitCode").asInt() < -255 || root.path("exitCode").asInt() > 255
                || !root.path("timedOut").isBoolean()
                || root.size() != (root.has("error") ? 4 : 3)
                || (root.has("error") && !root.path("error").isTextual()))
            throw new IOException("Invalid worker response");
        // Worker replies are untrusted text. Angular must display output with interpolation, never HTML.
        if ("INVALID_EXPORT_FORMAT".equals(root.path("error").asText()))
            throw new LabApiException(HttpStatus.BAD_REQUEST, "INVALID_EXPORT_FORMAT", "Supported export formats are csv and json");
        if (root.has("error") && !"OUTPUT_LIMIT".equals(root.path("error").asText()))
            throw new IOException("Worker rejected request");
        return new ExportResult(root.path("output").asText(), root.path("exitCode").asInt(), root.path("timedOut").asBoolean());
    }

    private static void await(Selector selector, SelectionKey key, int operation, long expires) throws IOException {
        key.interestOps(operation);
        checkDeadline(expires);
        long millis = Math.max(1, (expires - System.nanoTime() + 999999) / 1000000);
        selector.select(millis);
        selector.selectedKeys().clear();
        checkDeadline(expires);
    }

    private static void checkDeadline(long expires) throws IOException {
        if (Thread.currentThread().isInterrupted() || System.nanoTime() >= expires)
            throw new IOException("Worker deadline exceeded");
    }

    public record ExportResult(String output, int exitCode, boolean timedOut) { }
}
