package com.passwordvault.local.core;

import com.passwordvault.local.core.lan.LanVaultAccessGate;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

final class LanVaultAccessGateTest {
    private LanVaultAccessGateTest() {
    }

    static void run() {
        exclusiveMutationWaitsForInFlightLanRequest();
        System.out.println("PASS LanVaultAccessGateTest");
    }

    private static void exclusiveMutationWaitsForInFlightLanRequest() {
        LanVaultAccessGate gate = new LanVaultAccessGate();
        CountDownLatch lanEntered = new CountDownLatch(1);
        CountDownLatch releaseLan = new CountDownLatch(1);
        AtomicBoolean lanCompleted = new AtomicBoolean();
        AtomicBoolean exclusiveEnteredTooEarly = new AtomicBoolean();

        Thread lan = new Thread(() -> gate.runLanRequest(() -> {
            lanEntered.countDown();
            await(releaseLan);
            lanCompleted.set(true);
            return null;
        }), "test LAN request");
        lan.start();
        await(lanEntered);

        Thread exclusive = new Thread(() -> gate.runExclusiveMutation(() -> {
            if (!lanCompleted.get()) exclusiveEnteredTooEarly.set(true);
        }), "test exclusive vault mutation");
        exclusive.start();
        waitUntilBlocked(exclusive);
        assertTrue(!exclusiveEnteredTooEarly.get(), "exclusive mutation entered before LAN request drained");

        releaseLan.countDown();
        join(lan);
        join(exclusive);
        assertTrue(lanCompleted.get(), "LAN request must complete");
        assertTrue(!exclusiveEnteredTooEarly.get(), "exclusive mutation must run after LAN request");
    }

    private static void waitUntilBlocked(Thread thread) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2L);
        while (System.nanoTime() < deadline) {
            Thread.State state = thread.getState();
            if (state == Thread.State.WAITING || state == Thread.State.BLOCKED) return;
            Thread.yield();
        }
        throw new AssertionError("exclusive mutation did not block behind LAN request");
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(2L, TimeUnit.SECONDS)) throw new AssertionError("timed out waiting for test latch");
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AssertionError("test interrupted", exception);
        }
    }

    private static void join(Thread thread) {
        try {
            thread.join(2_000L);
            if (thread.isAlive()) throw new AssertionError("test thread did not finish");
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AssertionError("test interrupted", exception);
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
