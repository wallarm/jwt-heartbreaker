package pingvin;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import lombok.SneakyThrows;
import org.apache.commons.lang.StringUtils;
import pingvin.tokenposition.Config;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class JwtPublicSecretsTab implements ITab {

    final JPanel panel;
    final JTable urlsTable;
    final DefaultTableModel urlsTableModel;

    @SneakyThrows
    public JwtPublicSecretsTab(IBurpExtenderCallbacks callbacks) {
        panel = new JPanel();
        panel.setLayout(new BorderLayout());

        urlsTableModel = new DefaultTableModel(new String[]{"URL", "Count"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                if (column == 1) {
                    return false;
                }

                return super.isCellEditable(row, column);
            }
        };
        final Map<URL, Integer> keys = JwtKeyProvider.getSecrets();
        for (Map.Entry<URL, Integer> key : keys.entrySet()) {
            urlsTableModel.addRow(new Object[]{key.getKey().toString(), key.getValue()});
        }
        urlsTableModel.addRow(new String[]{null, null});

        urlsTable = new JTable(urlsTableModel);
        urlsTableModel.addTableModelListener(e -> {
            if (e.getType() == TableModelEvent.UPDATE && e.getColumn() == 0) {
                Object valueAt = urlsTableModel.getValueAt(e.getFirstRow(), 0);
                if (valueAt == null || StringUtils.isBlank((String) valueAt)) {
                    urlsTableModel.removeRow(e.getFirstRow());
                }

                Object valueAt1 = urlsTableModel.getValueAt(urlsTableModel.getRowCount() - 1, 0);
                if (valueAt1 != null && StringUtils.isNotBlank((String) valueAt1)) {
                    urlsTableModel.addRow(new String[]{null, null});
                }
            }
        });

        final JScrollPane tableScrollPane = new JScrollPane(urlsTable);
        panel.add(tableScrollPane, BorderLayout.CENTER);

        final JPanel updateAndCount = new JPanel(new BorderLayout());
        final JButton updateButton = new JButton();
        updateButton.setText("Update");
        updateButton.addActionListener(this::update);
        updateAndCount.add(updateButton, BorderLayout.CENTER);

        final JPanel linksPanel = new JPanel(new FlowLayout());
        final JButton sourceButton = new JButton();
        sourceButton.setText("Source Code");
        final URI sourceUri = new URI("https://github.com/Wallarm/jwt-heartbreaker");
        sourceButton.addActionListener(e -> openLink(sourceUri));
        linksPanel.add(sourceButton);

        final JButton releaseNotesButton = new JButton();
        releaseNotesButton.setText("Release Notes");
        final URI releaseNotesUri = new URI("https://lab.wallarm.com/jwt-heartbreaker/");
        releaseNotesButton.addActionListener(e -> openLink(releaseNotesUri));
        linksPanel.add(releaseNotesButton);
        updateAndCount.add(linksPanel, BorderLayout.EAST);
        panel.add(updateAndCount, BorderLayout.SOUTH);

        callbacks.customizeUiComponent(panel);
    }

    @SneakyThrows
    private void openLink(final URI uri) {
        if (Desktop.isDesktopSupported()) {
            Desktop.getDesktop().browse(uri);
        }
    }

    @SneakyThrows
    private void update(ActionEvent e) {
        int lastRow = urlsTableModel.getRowCount();
        final List<String> secrets = new ArrayList<>();
        for (int i = 0; i < lastRow; i++) {
            Object valueAt = urlsTableModel.getValueAt(i, 0);
            if (valueAt != null && StringUtils.isNotBlank((String) valueAt)) {
                try {
                    new URL((String) valueAt);
                } catch (Exception ex) {
                    continue;
                }
                secrets.add((String) valueAt);
            }
        }

        Config.updateSecrets(secrets);
        Config.loadConfig();
        JwtKeyProvider.loadKeys();

        urlsTableModel.getDataVector().clear();
        urlsTableModel.fireTableRowsDeleted(0, lastRow - 1);

        final Map<URL, Integer> keys = JwtKeyProvider.getSecrets();
        for (Map.Entry<URL, Integer> key : keys.entrySet()) {
            urlsTableModel.addRow(new Object[]{key.getKey().toString(), key.getValue()});
        }
        urlsTableModel.addRow(new String[]{null, null});
    }

    @Override
    public String getTabCaption() {
        return "JWT heartbreaker";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }

}
