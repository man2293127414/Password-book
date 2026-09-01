package com.passwordvault.local.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

final class AndroidDeviceCiContractTest {
    private AndroidDeviceCiContractTest() {
    }

    static void run() {
        String buildScript = read("app/build.gradle.kts");
        String workflow = read(".github/workflows/build-apk.yml");

        assertContains(buildScript, "create(\"pixel2Api35\")");
        assertContains(buildScript, "apiLevel = 35");
        assertContains(buildScript, "systemImageSource = \"aosp\"");
        assertContains(workflow, "pixel2Api35DebugAndroidTest");
        assertContains(
                workflow,
                "-Pandroid.testoptions.manageddevices.emulator.gpu=swiftshader_indirect"
        );
        assertNotContains(workflow, "name: Compile Android device tests");
        System.out.println("PASS AndroidDeviceCiContractTest");
    }

    private static String read(String path) {
        try {
            String projectRoot = System.getProperty("passwordvault.projectRoot", ".");
            return new String(
                    Files.readAllBytes(Paths.get(projectRoot).resolve(path)),
                    StandardCharsets.UTF_8
            );
        } catch (IOException error) {
            throw new AssertionError("Unable to read CI contract file: " + path, error);
        }
    }

    private static void assertContains(String text, String expected) {
        if (!text.contains(expected)) {
            throw new AssertionError("Expected CI contract to contain: " + expected);
        }
    }

    private static void assertNotContains(String text, String unexpected) {
        if (text.contains(unexpected)) {
            throw new AssertionError("Expected CI contract to omit: " + unexpected);
        }
    }
}
