package com.termux.shared.termux;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class TermuxConstantsIdentityTest {

    @Test
    public void runtimeIdentityUsesProductPackageAndPrefix() {
        assertEquals("com.prodysor.term", TermuxConstants.TERMUX_PACKAGE_NAME);
        assertEquals("/data/data/com.prodysor.term", TermuxConstants.TERMUX_INTERNAL_PRIVATE_APP_DATA_DIR_PATH);
        assertEquals("/data/data/com.prodysor.term/files/home", TermuxConstants.TERMUX_HOME_DIR_PATH);
        assertEquals("/data/data/com.prodysor.term/files/usr", TermuxConstants.TERMUX_PREFIX_DIR_PATH);
    }

    @Test
    public void implementationClassNamesKeepUpstreamJavaNamespace() {
        assertEquals("com.termux", TermuxConstants.TERMUX_APP_JAVA_PACKAGE_NAME);
        assertEquals("com.termux.BuildConfig", TermuxConstants.TERMUX_APP.BUILD_CONFIG_CLASS_NAME);
        assertEquals("com.termux.app.TermuxActivity", TermuxConstants.TERMUX_APP.TERMUX_ACTIVITY_NAME);
        assertEquals("com.termux.app.TermuxService", TermuxConstants.TERMUX_APP.TERMUX_SERVICE_NAME);
        assertEquals("com.termux.app.RunCommandService", TermuxConstants.TERMUX_APP.RUN_COMMAND_SERVICE_NAME);
    }
}
