# SQLi Helper Burp Extension

This extension is a Burp Suite helper for SQL injection workflows. It is designed to make it easier to generate and test payloads against a live application and iterate over an extracted value one character at a time.

## What it does

The extension provides a dedicated Burp tab for running an extraction flow with:

- URL parameter injection
- Cookie injection
- POST parameter injection
- configurable target URL and HTTP method
- database type selection (Auto, MySQL, PostgreSQL, MSSQL, Oracle, Generic)
- optional DBMS fingerprinting, with automatic dialect selection during iteration
- Boolean blind, time-based, error-based, UNION-based, stacked/multiple, and custom payload modes
- boolean success keyword detection
- time-based response detection using a configurable delay threshold
- error-based response detection using common SQL error markers
- a character-by-character extraction loop over a configurable charset
- configurable row offset, starting position, maximum position, and delay between requests
- an output area that shows status messages and the extracted result as it is built
- a copy button that becomes active after an iteration finishes with a non-empty result
- marker-based extraction for UNION and stacked-query workflows
- custom SQL templates with `{{POS}}`, `{{CHAR}}`, `{{ASCII}}`, and `{{DELAY}}` placeholders

The extension is intended for practical testing against targets that reveal a success condition in the response body, response status, response timing, or database error text. Use it only against systems you are authorized to test.

## Typical workflow

1. Start from a request in a Burp message editor, such as Repeater or Proxy.
2. Use the right-click context menu and choose **Send to SQLi Helper**. The extension uses the selected request as the base request and attempts to infer the injection source and parameter name.
3. Choose the injection source:
   - URL parameter
   - Cookie
   - POST parameter
4. Enter the relevant parameter name, URL, target table/column, and detection settings.
5. Select an injection mode and DBMS, or use **Fingerprint DBMS** when the target supports the extension's probes.
6. Generate and optionally test a payload, then start the corresponding iteration.
7. The extension tests characters from the configured charset and appends successful matches to the extracted value.
8. When the iteration ends, the final extracted result is shown in the output area. The result can be copied when it is non-empty.

## Boolean SQLi matching

This mode is configured around boolean blind SQLi detection. Rather than assuming any response difference is a hit, it looks for configured, comma-separated success keywords in the response body. For example, if the application responds with "Welcome back" when a condition is true, the extension treats that as a successful match for the current character test.

Time-based mode compares each response duration with a baseline response and the configured threshold. Error-based mode checks for known SQL error text. Custom mode lets you choose HTTP status, response keyword, SQL error text, or time-based detection for a user-supplied template.

## UNION and stacked extraction

UNION-based and stacked-query iteration use a response marker to identify a matching character. The default marker is `SQLI_MATCH`; change it to a value that is unique to the target response and unlikely to appear in normal traffic. The generated conditional payload returns that marker only when the current character matches.

The UNION panel also supports a configurable column count and output column. Stacked mode uses its configured second statement for payload previews and conditional marker statements during extraction. Payload syntax varies by DBMS; the generated MSSQL error-based payload is a placeholder that may require manual adaptation.

## Custom payloads

Custom mode accepts a template containing at least one of these placeholders:

- `{{POS}}` — current character position
- `{{CHAR}}` — candidate character
- `{{ASCII}}` — numeric value of the candidate character
- `{{DELAY}}` — configured sleep duration in seconds

The custom detection setting determines how a candidate is considered a match. The custom payload is generated and previewed using the first character in the configured charset.

## Project structure

- `src/main/java/com/example/sqli/MontoyaExtension.java` contains the Burp extension logic, UI, request handling, and SQLi iteration flow.
- `src/test/java/com/example/sqli/MontoyaExtensionTest.java` contains regression tests for parameter injection, iteration, payload rendering, payload generation, and detection behavior.

## Build

The project is built with Maven:

```bash
mvn clean package
```

To run the tests:

```bash
mvn test
```

The project uses Java 21 and the provided Montoya API dependency `net.portswigger.burp.extensions:montoya-api:2026.7`. If that artifact is unavailable from the configured Maven repositories, provide a local Montoya JAR with:

```bash
mvn clean package -Puse-montoya -Dmontoya.jar=/absolute/path/to/montoya.jar
```

## Usage in Burp

1. Build the extension JAR with Maven.
2. In Burp, open Extender → Extensions → Add.
3. Load the generated JAR.
4. Open the SQLi Helper tab from the Burp extension UI.
5. Or right-click a request in a Burp message editor and choose **Send to SQLi Helper**. The provider currently registers this item for message-editor request invocations.

## Notes

- Boolean success keywords must be adjusted to the target application.
- DBMS fingerprinting is heuristic and returns `Generic` when no probe matches; verify the selected dialect before relying on generated payload syntax.
- The generated payload templates are intended to help with a real SQLi testing process, but the exact success condition should always match the target’s response behavior.
