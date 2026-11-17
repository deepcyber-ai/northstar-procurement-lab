package com.deepcyber.training.service;

import com.deepcyber.training.api.LabApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.HttpStatus;

import java.io.ByteArrayOutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ExportWorkerServiceTests {
    @TempDir Path directory;

    @Test void sendsOnlyTheMinimalSyntheticContractAndReturnsText() throws Exception {
        try (var worker = new FakeWorker("{\"output\":\"CMD01_PROOF\\n\",\"exitCode\":0,\"timedOut\":false}\n", 0)) {
            var result = new ExportWorkerService(worker.path.toString()).export("ORD-A-100", "csv; printf CMD01_PROOF", true);
            assertThat(result.output()).isEqualTo("CMD01_PROOF\n");
            assertThat(result.exitCode()).isZero();
            assertThat(result.timedOut()).isFalse();
            var request = new ObjectMapper().readTree(worker.received.get(1, TimeUnit.SECONDS));
            assertThat(request.size()).isEqualTo(5);
            assertThat(request.path("version").asInt()).isEqualTo(1);
            assertThat(request.path("vulnerable").asBoolean()).isTrue();
            assertThat(request.path("order").size()).isEqualTo(1);
            assertThat(request.path("order").path("id").asText()).isEqualTo("ORD-A-100");
        }
    }

    @Test void fixedModeRejectsShellSyntaxBeforeConnecting() {
        var worker = new ExportWorkerService(directory.resolve("missing").toString());
        for (String format : new String[]{"csv; printf marker", "", "x".repeat(129), "csv\n", "csv\u0000"}) {
            assertThatThrownBy(() -> worker.export("ORD-A-100", format, false))
                    .isInstanceOfSatisfying(LabApiException.class, error -> assertThat(error.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST));
        }
    }

    @Test void missingWorkerFailsClosedWithoutFallbackExecution() {
        var worker = new ExportWorkerService(directory.resolve("missing").toString());
        assertUnavailable(() -> worker.export("ORD-A-100", "csv", true));
    }

    @Test void stalledWorkerHasAnOverallDeadline() throws Exception {
        try (var worker = new FakeWorker(null, 1000)) {
            long started = System.nanoTime();
            assertUnavailable(() -> new ExportWorkerService(worker.path.toString(), Duration.ofMillis(100))
                    .export("ORD-A-100", "csv", false));
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(1));
        }
    }

    @Test void invalidAndOversizedRepliesAreNotTrusted() throws Exception {
        String[] replies = {"{}\n", "no JSON\n", "{\"output\":\"ok\",\"exitCode\":0,\"timedOut\":false}",
                "{\"output\":\"ok\",\"output\":\"dup\",\"exitCode\":0,\"timedOut\":false}\n",
                "{\"output\":\"ok\",\"exitCode\":999,\"timedOut\":false}\n", "x".repeat(65537) + "\n",
                "{\"output\":\"" + "x".repeat(24577) + "\",\"exitCode\":0,\"timedOut\":false}\n"};
        for (String reply : replies) {
            try (var worker = new FakeWorker(reply, 0)) {
                assertUnavailable(() -> new ExportWorkerService(worker.path.toString()).export("ORD-A-100", "csv", true));
            }
        }
    }

    @Test void timeoutAndOutputLimitAreBoundedResultsNotTransportFailures() throws Exception {
        try (var worker = new FakeWorker("{\"output\":\"partial\",\"exitCode\":124,\"timedOut\":true}\n", 0)) {
            assertThat(new ExportWorkerService(worker.path.toString()).export("ORD-A-100", "csv", true).timedOut()).isTrue();
        }
        try (var worker = new FakeWorker("{\"output\":\"partial\",\"exitCode\":125,\"timedOut\":false,\"error\":\"OUTPUT_LIMIT\"}\n", 0)) {
            assertThat(new ExportWorkerService(worker.path.toString()).export("ORD-A-100", "csv", true).exitCode()).isEqualTo(125);
        }
    }

    @Test void resetNeverAcceptsAPayloadOrPath() throws Exception {
        try (var worker = new FakeWorker("{\"output\":\"reset\",\"exitCode\":0,\"timedOut\":false}\n", 0)) {
            new ExportWorkerService(worker.path.toString()).reset();
            var request = new ObjectMapper().readTree(worker.received.get(1, TimeUnit.SECONDS));
            assertThat(request.size()).isEqualTo(2);
            assertThat(request.path("action").asText()).isEqualTo("reset");
        }
    }

    private void assertUnavailable(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOfSatisfying(LabApiException.class, error -> {
            assertThat(error.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
            assertThat(error.getCode()).isEqualTo("EXPORT_WORKER_UNAVAILABLE");
            assertThat(error.getMessage()).doesNotContain(directory.toString());
        });
    }

    private class FakeWorker implements AutoCloseable {
        final Path path = directory.resolve("s" + System.nanoTime());
        final ServerSocketChannel server;
        final ExecutorService executor = Executors.newSingleThreadExecutor();
        final Future<String> received;

        FakeWorker(String reply, long delayMillis) throws Exception {
            server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
            server.bind(UnixDomainSocketAddress.of(path));
            received = executor.submit(() -> {
                try (SocketChannel client = server.accept()) {
                    ByteArrayOutputStream request = new ByteArrayOutputStream();
                    ByteBuffer one = ByteBuffer.allocate(1);
                    while (request.size() < 65536) {
                        if (client.read(one) < 0) break;
                        one.flip();
                        if (!one.hasRemaining()) continue;
                        byte value = one.get();
                        one.clear();
                        if (value == '\n') break;
                        request.write(value);
                    }
                    if (delayMillis > 0) Thread.sleep(delayMillis);
                    if (reply != null) {
                        ByteBuffer response = ByteBuffer.wrap(reply.getBytes(StandardCharsets.UTF_8));
                        try { while (response.hasRemaining()) client.write(response); }
                        catch (java.io.IOException expectedClientCloseOnInvalidReply) { }
                    }
                    return request.toString(StandardCharsets.UTF_8);
                }
            });
        }

        @Override public void close() throws Exception {
            server.close();
            executor.shutdownNow();
            assertThat(executor.awaitTermination(2, TimeUnit.SECONDS)).isTrue();
        }
    }
}
