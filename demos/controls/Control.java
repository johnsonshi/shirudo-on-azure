import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.sql.Statement;
import java.util.Base64;

/** Fixed local fixtures. There are no command-line inputs to either operation. */
final class Control {
    // A non-public interface puts the proxy in the application's package, not jdk.proxy.
    interface FixtureStatement extends Statement {}
    static final String READ = "SELECT 7";
    static final String MARKER = "SELECT 7 WHERE 8 > 3 AND 4 = 5";

    static void jdbc() throws Exception {
        // Real, empty SQLite in memory; the Statement adapter is a fixture, not a JDBC driver.
        // Its two constants are the entire protocol. It never accepts general SQL.
        var s = (Statement) Proxy.newProxyInstance(Control.class.getClassLoader(),
            new Class<?>[]{FixtureStatement.class}, (obj, method, args) -> {
                if (!method.getName().equals("execute") || args.length != 1)
                    throw new UnsupportedOperationException();
                String q = (String) args[0];
                if (!q.equals(READ) && !q.equals(MARKER)) throw new IllegalArgumentException();
                var p = new ProcessBuilder("/usr/bin/python3", "-I", "-c",
                    "import sqlite3,sys; c=sqlite3.connect(':memory:'); c.execute('PRAGMA query_only=ON'); " +
                    "print(c.execute(sys.argv[1]).fetchall())", q).start();
                String rows = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
                if (p.waitFor() != 0 || !rows.equals(q.equals(READ) ? "[(7,)]" : "[]"))
                    throw new IOException("unexpected fixed SQLite read");
                return true;
            });
        if (!s.execute(READ)) throw new AssertionError();
        System.out.println("fixed-read=7");
        try {
            if (!s.execute(MARKER)) throw new AssertionError();
            System.out.println("fixed-marker=empty");
        } catch (SecurityException ex) {
            if (!"Request blocked by RASP: Malicious SQL patterns detected.".equals(ex.getMessage())) throw ex;
            System.out.println("fixed-marker=policy-exception");
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("jdbc")) { jdbc(); return; }
        if (args.length != 1 || !args[0].equals("base64")) throw new IllegalArgumentException();
        try (var input = new BufferedReader(new InputStreamReader(System.in))) {
            for (String line; (line = input.readLine()) != null; ) {
                if (line.equals("quit")) break;
                if (!line.equals("read")) throw new IllegalArgumentException();
                String value = new String(Base64.getDecoder().decode("Y29udHJvbA=="), StandardCharsets.UTF_8);
                System.out.printf("%d %d %s%n", ProcessHandle.current().pid(),
                    ManagementFactory.getRuntimeMXBean().getStartTime(), value);
                System.out.flush();
            }
        }
    }
}
