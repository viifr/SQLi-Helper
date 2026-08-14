# SQLi Burp Extension

Simple Burp Suite extension to help generate blind SQLi payloads (boolean and time-based).

Build and run

- Copy `burpsuite_pro.jar` or your Burp Extender API JAR path somewhere accessible.
- Compile with javac against the Burp extender API jar, for example:

```bash
mkdir -p out
javac -cp "/path/to/burp-extender-api.jar" -d out $(find src/main/java -name "*.java")
jar cvf sqli-burp-extension.jar -C out .
```

- Or use Maven by adding the Burp API jar to your local repository and running `mvn package`.

Usage

1. Load the extension JAR in Burp (Extender → Extensions → Add).
2. Open the `SQLi Helper` tab.
3. Enter `table` and `column`, choose injection type, optionally set row `LIMIT` offset and character `Position`.
4. Click `Generate`, then `Copy` and paste the payload into your request.

Notes

- The extension generates simple templates; adjust the generated payloads for your target DBMS and encoding.
- Time-based payloads use `SLEEP(5)` (MySQL). Modify generated templates in `BurpExtender.java` if needed.
