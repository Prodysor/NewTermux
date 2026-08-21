package com.termux.app;

import android.content.Context;

import com.termux.shared.shell.command.ExecutionCommand;
import com.termux.shared.termux.TermuxConstants;
import com.termux.shared.termux.shell.command.runner.terminal.TermuxSession;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Persists the live session list (name + cwd + failsafe flag) to disk so that
 * if the com.termux process is torn down in the background (e.g. while a
 * fullscreen game is in the foreground), the next launch can recreate the same
 * set of tabs.
 *
 * IMPORTANT — this restores the VIEW, not the compute:
 *   What IS persisted (per session): shellName, workingDirectory, isFailsafe.
 *   What is NOT persisted: the PTY, scrollback, and any in-flight child
 *   processes. Those die with the PID and cannot be revived. A `claude` CLI
 *   that was running is gone — reopen the restored tab and `claude --continue`
 *   to resume conversation state from ~/.claude/.
 *
 * All I/O here is best-effort: a persistence failure must never crash the app.
 */
public final class SessionStatePersister {

    private static final String DIR_NAME  = ".termux";
    private static final String FILE_NAME = "session_state.json";

    public static final class Snapshot {
        public String  name;
        public String  cwd;
        public boolean failsafe;
    }

    private static File stateFile() {
        File dir = new File(TermuxConstants.TERMUX_FILES_DIR_PATH, DIR_NAME);
        if (!dir.exists()) dir.mkdirs();
        return new File(dir, FILE_NAME);
    }

    /** Best-effort snapshot of the current session list. Never throws. Atomic rename on success. */
    public static void save(Context ctx, List<TermuxSession> sessions) {
        if (sessions == null) return;
        try {
            JSONArray arr = new JSONArray();
            for (TermuxSession s : sessions) {
                if (s == null) continue;
                ExecutionCommand ec = s.getExecutionCommand();
                if (ec == null) continue;
                JSONObject o = new JSONObject();
                o.put("name",     ec.shellName        == null ? "" : ec.shellName);
                o.put("cwd",      ec.workingDirectory == null ? "" : ec.workingDirectory);
                o.put("failsafe", ec.isFailsafe);
                arr.put(o);
            }
            File f   = stateFile();
            File tmp = new File(f.getParentFile(), FILE_NAME + ".tmp");
            try (FileWriter w = new FileWriter(tmp)) {
                w.write(arr.toString());
            }
            // POSIX rename = atomic on same filesystem.
            if (!tmp.renameTo(f)) {
                tmp.delete();
            }
        } catch (Exception ignored) { }
    }

    /** Best-effort load of the last snapshot. Never throws; returns an empty list on any failure. */
    public static List<Snapshot> load() {
        List<Snapshot> out = new ArrayList<>();
        File f = stateFile();
        if (!f.exists()) return out;
        try {
            String json = new String(Files.readAllBytes(Paths.get(f.getAbsolutePath())));
            JSONArray arr = new JSONArray(json);
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.getJSONObject(i);
                Snapshot s = new Snapshot();
                s.name     = o.optString("name", "");
                s.cwd      = o.optString("cwd",  "");
                s.failsafe = o.optBoolean("failsafe", false);
                out.add(s);
            }
        } catch (Exception ignored) { }
        return out;
    }

    /** Drop the snapshot so a subsequent launch starts fresh (used on explicit stop). */
    public static void clear() {
        try {
            File f = stateFile();
            if (f.exists()) f.delete();
        } catch (Exception ignored) { }
    }

    private SessionStatePersister() { }
}
