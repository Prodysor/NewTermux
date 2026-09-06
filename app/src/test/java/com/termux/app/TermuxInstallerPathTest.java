package com.termux.app;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;

public class TermuxInstallerPathTest {

    @Rule
    public final TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void resolveStrictChildAllowsSafeChildren() throws Exception {
        File root = temporaryFolder.newFolder("usr-staging");

        Assert.assertEquals(new File(root, "bin/bash").getCanonicalFile(),
            TermuxInstaller.resolveStrictChild(root, "bin/bash", false));
        Assert.assertEquals(new File(root, "etc/apt/sources.list").getCanonicalFile(),
            TermuxInstaller.resolveStrictChild(root, "./etc/apt/sources.list", true));
    }

    @Test
    public void resolveStrictChildRejectsEscapesAndRoot() throws Exception {
        File root = temporaryFolder.newFolder("usr-staging");

        assertPathRejected(root, "../owned");
        assertPathRejected(root, "a/../../owned");
        assertPathRejected(root, "../usr-staging-evil/owned");
        assertPathRejected(root, "/absolute");
        assertPathRejected(root, null);
        assertPathRejected(root, "");
        assertPathRejected(root, "./");
        assertPathRejected(root, "./etc/apt/sources.list");
        assertPathRejected(root, "a/../b");
        assertPathRejected(root, "a//b");
        assertPathRejected(root, "a\\b");
    }

    @Test
    public void symlinkTargetsInsideFinalPrefixAreAllowed() throws Exception {
        File prefix = temporaryFolder.newFolder("usr");

        assertTargetAllowed(prefix, "bin/sh", "bash");
        assertTargetAllowed(prefix, "bin/terminfo", "../share/terminfo");
        assertTargetAllowed(prefix, "share/doc/bash/LICENSE", "../../LICENSES/GPL-3.0.txt");
        assertTargetAllowed(prefix, "bin/absolute", new File(prefix, "lib/libc.so").getAbsolutePath());
    }

    @Test
    public void symlinkTargetsOutsideFinalPrefixAreRejected() throws Exception {
        File prefix = temporaryFolder.newFolder("usr");

        assertTargetRejected(prefix, "bin/link", "../../../home/owned");
        assertTargetRejected(prefix, "bin/link", temporaryFolder.getRoot().getAbsolutePath());
        assertTargetRejected(prefix, "bin/link", "/system/bin/sh");
        assertTargetRejected(prefix, "bin/link", "");
    }

    private static void assertPathRejected(File root, String path) {
        Assert.assertThrows(IOException.class, () -> TermuxInstaller.resolveStrictChild(root, path, false));
    }

    private static void assertTargetAllowed(File prefix, String linkPath, String target) throws Exception {
        File finalLink = TermuxInstaller.resolveStrictChild(prefix, linkPath, true);
        TermuxInstaller.requireSymlinkTargetInsidePrefix(prefix, finalLink, target);
    }

    private static void assertTargetRejected(File prefix, String linkPath, String target) throws Exception {
        File finalLink = TermuxInstaller.resolveStrictChild(prefix, linkPath, true);
        Assert.assertThrows(IOException.class,
            () -> TermuxInstaller.requireSymlinkTargetInsidePrefix(prefix, finalLink, target));
    }
}
