package com.example.taskmanager.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableModel;

import com.example.taskmanager.model.Task;
import com.example.taskmanager.service.ApiService;
import com.example.taskmanager.service.AuthService;

public class TaskPanel extends JPanel {
    private final ApiService apiService;
    private final AuthService authService;
    private final MainWindow mainWindow;
    
    private final JTable userTable;
    private final DefaultTableModel tableModel;
    private final JButton refreshButton;
    private final JButton addButton;
    private final JButton editButton;
    private final JButton deleteButton;
    private final JButton logoutButton;
    
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");
    private static final int BASE_FONT_SIZE = 12;
    private double scaleFactor = 1.0;

    public TaskPanel(ApiService apiService, AuthService authService, MainWindow mainWindow) {
        this.apiService = apiService;
        this.authService = authService;
        this.mainWindow = mainWindow;
        
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        String[] columnNames = {"ID", "Email", "Full Name", "Role", "Status", "Created Date", "Updated Date", "Phone", "Address", "Birth Date", "Identity Number"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        userTable = new JTable(tableModel);
        userTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        userTable.getTableHeader().setReorderingAllowed(false);
        userTable.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        userTable.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, (int) (BASE_FONT_SIZE * scaleFactor)));
        
        JScrollPane scrollPane = new JScrollPane(userTable);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        refreshButton = new JButton("Refresh");
        refreshButton.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        refreshButton.addActionListener(e -> refreshUsers());
        
        addButton = new JButton("Add User");
        addButton.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        addButton.addActionListener(e -> showAddUserDialog());
        
        editButton = new JButton("Edit User");
        editButton.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        editButton.addActionListener(e -> {
            int selectedRow = userTable.getSelectedRow();
            if (selectedRow >= 0) {
                showEditUserDialog(getUserFromSelectedRow());
            } else {
                JOptionPane.showMessageDialog(this, 
                    "Please select a user to edit", 
                    "Selection Required", 
                    JOptionPane.INFORMATION_MESSAGE);
            }
        });
        
        deleteButton = new JButton("Delete User");
        deleteButton.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        deleteButton.addActionListener(e -> {
            int selectedRow = userTable.getSelectedRow();
            if (selectedRow >= 0) {
                confirmAndDeleteUser();
            } else {
                JOptionPane.showMessageDialog(this, 
                    "Please select a user to delete", 
                    "Selection Required", 
                    JOptionPane.INFORMATION_MESSAGE);
            }
        });
        
        logoutButton = new JButton("Logout");
        logoutButton.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        logoutButton.addActionListener(e -> {
            authService.logout();
            mainWindow.showLoginPanel();
        });
        
        buttonPanel.add(refreshButton);
        buttonPanel.add(addButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(logoutButton);
        
        add(buttonPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        
        refreshUsers();
    }

    public void updateFonts(double scaleFactor) {
        this.scaleFactor = scaleFactor;
        Font scaledFont = new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor));
        Font scaledBoldFont = new Font("Segoe UI", Font.BOLD, (int) (BASE_FONT_SIZE * scaleFactor));
        
        userTable.setFont(scaledFont);
        userTable.getTableHeader().setFont(scaledBoldFont);
        userTable.revalidate();
        userTable.repaint();
        
        refreshButton.setFont(scaledFont);
        addButton.setFont(scaledFont);
        editButton.setFont(scaledFont);
        deleteButton.setFont(scaledFont);
        logoutButton.setFont(scaledFont);
    }

    public void refreshUsers() {
        refreshButton.setEnabled(false);
        refreshButton.setText("Loading...");

        SwingWorker<List<Task>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<Task> doInBackground() {
                return apiService.getUsers();
            }

            @Override
            protected void done() {
                try {
                    List<Task> users = get();
                    System.out.println("User fetched: " + (users != null ? users.size() : 0) + " users");
                    updateUserTable(users != null ? users : Collections.emptyList());
                    refreshButton.setEnabled(true);
                    refreshButton.setText("Refresh");
                } catch (Exception e) {
                    e.printStackTrace();
                    JOptionPane.showMessageDialog(TaskPanel.this, 
                        "Error loading users: " + e.getMessage(), 
                        "Error", 
                        JOptionPane.ERROR_MESSAGE);
                    refreshButton.setEnabled(true);
                    refreshButton.setText("Refresh");
                }
            }
        };

        worker.execute();
    }

    private void updateUserTable(List<Task> users) {
        tableModel.setRowCount(0);
        System.out.println("Updating table with " + users.size() + " users");

        for (Task user : users) {
            Vector<Object> row = new Vector<>();
            row.add(user.getId() != null ? user.getId() : "");
            row.add(user.getEmail() != null ? user.getEmail() : "");
            row.add(user.getFullName() != null ? user.getFullName() : "");
            row.add(user.getRole() != null ? user.getRole() : "");
            row.add(user.getStatus() != null ? user.getStatus() : "");
            row.add(formatDateTime(user.getCreateDate()));
            row.add(formatDateTime(user.getUpdateDate()));
            row.add(user.getPhone() != null ? user.getPhone() : "");
            row.add(user.getAddress() != null ? user.getAddress() : "");
            row.add(formatDateTime(user.getBirthDate()));
            row.add(user.getIdentityNumber() != null ? user.getIdentityNumber() : "");
            tableModel.addRow(row);
        }

        userTable.repaint();
        userTable.revalidate();
    }

    private String formatDateTime(Object dateTime) {
        if (dateTime == null) return "";
        if (dateTime instanceof LocalDateTime) {
            return ((LocalDateTime) dateTime).format(DATE_FORMATTER);
        } else if (dateTime instanceof LocalDate) {
            return ((LocalDate) dateTime).format(DateTimeFormatter.ofPattern("yyyy-MM-dd"));
        }
        return "";
    }
    
    private Task getUserFromSelectedRow() {
        int selectedRow = userTable.getSelectedRow();
        if (selectedRow < 0) {
            return null;
        }

        Long id = (Long) tableModel.getValueAt(selectedRow, 0);
        String email = (String) tableModel.getValueAt(selectedRow, 1);
        String fullName = (String) tableModel.getValueAt(selectedRow, 2);
        String role = (String) tableModel.getValueAt(selectedRow, 3);
        String status = (String) tableModel.getValueAt(selectedRow, 4);
        LocalDateTime createDate = parseDateTime((String) tableModel.getValueAt(selectedRow, 5)) instanceof LocalDateTime 
            ? (LocalDateTime) parseDateTime((String) tableModel.getValueAt(selectedRow, 5)) : null;
        LocalDateTime updateDate = parseDateTime((String) tableModel.getValueAt(selectedRow, 6)) instanceof LocalDateTime 
            ? (LocalDateTime) parseDateTime((String) tableModel.getValueAt(selectedRow, 6)) : null;
        String phone = (String) tableModel.getValueAt(selectedRow, 7);
        String address = (String) tableModel.getValueAt(selectedRow, 8);
        LocalDate birthDate = parseDateTime((String) tableModel.getValueAt(selectedRow, 9)) instanceof LocalDate 
            ? (LocalDate) parseDateTime((String) tableModel.getValueAt(selectedRow, 9)) : null;
        String identityNumber = (String) tableModel.getValueAt(selectedRow, 10);

        Task user = new Task();
        user.setId(id);
        user.setEmail(email);
        user.setFullName(fullName);
        user.setRole(role);
        user.setStatus(status);
        user.setCreateDate(createDate);
        user.setUpdateDate(updateDate);
        user.setPhone(phone);
        user.setAddress(address);
        user.setBirthDate(birthDate);
        user.setIdentityNumber(identityNumber);

        return user;
    }

    private Object parseDateTime(String dateTimeStr) {
        if (dateTimeStr == null || dateTimeStr.isEmpty()) return null;
        try {
            return LocalDateTime.parse(dateTimeStr, DATE_FORMATTER);
        } catch (Exception e) {
            return LocalDate.parse(dateTimeStr, DateTimeFormatter.ofPattern("yyyy-MM-dd"));
        }
    }

    private void showAddUserDialog() {
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this), "Add New User", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize((int) (550 * scaleFactor), (int) (350 * scaleFactor));
        dialog.getContentPane().setBackground(new Color(240, 248, 255));
        dialog.setLocationRelativeTo(this);

        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        formPanel.setBackground(new Color(245, 245, 245));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JLabel emailLabel = new JLabel("Email:");
        emailLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JTextField emailField = new JTextField(20);
        emailField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        emailField.setEnabled(true);
        emailField.setBackground(Color.WHITE);
        emailField.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        emailField.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        JLabel fullNameLabel = new JLabel("Full Name:");
        fullNameLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JTextField fullNameField = new JTextField(20);
        fullNameField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        fullNameField.setEnabled(true);
        fullNameField.setBackground(Color.WHITE);
        fullNameField.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        fullNameField.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        JLabel roleLabel = new JLabel("Role:");
        roleLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JComboBox<String> roleComboBox = new JComboBox<>(new String[]{"admin"});
        roleComboBox.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        roleComboBox.setEnabled(true);
        roleComboBox.setBackground(Color.WHITE);
        roleComboBox.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        roleComboBox.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        JLabel statusLabel = new JLabel("Status:");
        statusLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JComboBox<String> statusComboBox = new JComboBox<>(new String[]{"Active", "Blocked"});
        statusComboBox.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        statusComboBox.setEnabled(true);
        statusComboBox.setBackground(Color.WHITE);
        statusComboBox.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        statusComboBox.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        JLabel phoneLabel = new JLabel("Phone:");
        phoneLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JTextField phoneField = new JTextField(20);
        phoneField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        phoneField.setEnabled(true);
        phoneField.setBackground(Color.WHITE);
        phoneField.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        phoneField.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        JLabel addressLabel = new JLabel("Address:");
        addressLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JTextField addressField = new JTextField(20);
        addressField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        addressField.setEnabled(true);
        addressField.setBackground(Color.WHITE);
        addressField.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        addressField.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        JLabel birthDateLabel = new JLabel("Birth Date (yyyy-MM-dd):");
        birthDateLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JTextField birthDateField = new JTextField(20);
        birthDateField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        birthDateField.setEnabled(true);
        birthDateField.setBackground(Color.WHITE);
        birthDateField.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        birthDateField.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        JLabel identityNumberLabel = new JLabel("Identity Number:");
        identityNumberLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JTextField identityNumberField = new JTextField(20);
        identityNumberField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        identityNumberField.setEnabled(true);
        identityNumberField.setBackground(Color.WHITE);
        identityNumberField.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        identityNumberField.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 0;
        formPanel.add(emailLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(emailField, gbc);

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 1;
        formPanel.add(fullNameLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(fullNameField, gbc);

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 2;
        formPanel.add(roleLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(roleComboBox, gbc);

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 3;
        formPanel.add(statusLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(statusComboBox, gbc);

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 4;
        formPanel.add(phoneLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(phoneField, gbc);

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 5;
        formPanel.add(addressLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(addressField, gbc);

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 6;
        formPanel.add(birthDateLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(birthDateField, gbc);

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 7;
        formPanel.add(identityNumberLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(identityNumberField, gbc);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));

        JButton saveButton = new JButton("Save");
        saveButton.setBackground(new Color(46, 139, 87));
        saveButton.setForeground(Color.BLACK);
        saveButton.setFocusPainted(false);
        saveButton.setFont(new Font("Segoe UI", Font.BOLD, (int) (BASE_FONT_SIZE * scaleFactor)));
        saveButton.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(34, 139, 34), 1),
            BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));

        JButton cancelButton = new JButton("Cancel");
        cancelButton.setBackground(new Color(255, 99, 71));
        cancelButton.setForeground(Color.BLACK);
        cancelButton.setFocusPainted(false);
        cancelButton.setFont(new Font("Segoe UI", Font.BOLD, (int) (BASE_FONT_SIZE * scaleFactor)));
        cancelButton.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(255, 69, 0), 1),
            BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));

        saveButton.addActionListener(e -> {
            String email = emailField.getText().trim();
            String fullName = fullNameField.getText().trim();
            String role = (String) roleComboBox.getSelectedItem();
            String status = (String) statusComboBox.getSelectedItem();
            String phone = phoneField.getText().trim();
            String address = addressField.getText().trim();
            Object birthDateObj = parseDateTime(birthDateField.getText().trim());
            LocalDate birthDate = birthDateObj instanceof LocalDate ? (LocalDate) birthDateObj : null;
            String identityNumber = identityNumberField.getText().trim();

            if (email.isEmpty() || fullName.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, 
                    "Email and Full Name are required", 
                    "Input Error", 
                    JOptionPane.ERROR_MESSAGE);
                return;
            }

            Task newUser = new Task();
            newUser.setEmail(email);
            newUser.setFullName(fullName);
            newUser.setRole(role);
            newUser.setStatus(status);
            newUser.setPhone(phone);
            newUser.setAddress(address);
            newUser.setBirthDate(birthDate);
            newUser.setIdentityNumber(identityNumber);
            newUser.setCreateDate(LocalDateTime.now());
            newUser.setUpdateDate(LocalDateTime.now());
//            // Tạo GoogleID ngẫu nhiên
//            newUser.setGoogleId(UUID.randomUUID().toString().replaceAll("-", ""));

            createUser(newUser);
            dialog.dispose();
        });

        cancelButton.addActionListener(e -> dialog.dispose());

        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);

        dialog.add(formPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);

        dialog.setFocusable(true);
        emailField.requestFocusInWindow();
        dialog.setVisible(true);
    }

    private void showEditUserDialog(Task user) {
        if (user == null) return;

        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this), "Edit User", Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize((int) (550 * scaleFactor), (int) (350 * scaleFactor));
        dialog.getContentPane().setBackground(new Color(240, 248, 255));
        dialog.setLocationRelativeTo(this);

        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        formPanel.setBackground(new Color(245, 245, 245));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JLabel emailLabel = new JLabel("Email:");
        emailLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JTextField emailField = new JTextField(user.getEmail() != null ? user.getEmail() : "", 20);
        emailField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        emailField.setEnabled(true);
        emailField.setBackground(Color.WHITE);
        emailField.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        emailField.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        JLabel fullNameLabel = new JLabel("Full Name:");
        fullNameLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JTextField fullNameField = new JTextField(user.getFullName() != null ? user.getFullName() : "", 20);
        fullNameField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        fullNameField.setEnabled(true);
        fullNameField.setBackground(Color.WHITE);
        fullNameField.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        fullNameField.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        JLabel roleLabel = new JLabel("Role:");
        roleLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JComboBox<String> roleComboBox = new JComboBox<>(new String[]{"admin"});
        roleComboBox.setSelectedItem(user.getRole() != null ? user.getRole() : "admin");
        roleComboBox.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        roleComboBox.setEnabled(true);
        roleComboBox.setBackground(Color.WHITE);
        roleComboBox.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        roleComboBox.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        JLabel statusLabel = new JLabel("Status:");
        statusLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JComboBox<String> statusComboBox = new JComboBox<>(new String[]{"Active", "Blocked"});
        statusComboBox.setSelectedItem(user.getStatus() != null ? user.getStatus() : "Active");
        statusComboBox.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        statusComboBox.setEnabled(true);
        statusComboBox.setBackground(Color.WHITE);
        statusComboBox.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        statusComboBox.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        JLabel phoneLabel = new JLabel("Phone:");
        phoneLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JTextField phoneField = new JTextField(user.getPhone() != null ? user.getPhone() : "", 20);
        phoneField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        phoneField.setEnabled(true);
        phoneField.setBackground(Color.WHITE);
        phoneField.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        phoneField.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        JLabel addressLabel = new JLabel("Address:");
        addressLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JTextField addressField = new JTextField(user.getAddress() != null ? user.getAddress() : "", 20);
        addressField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        addressField.setEnabled(true);
        addressField.setBackground(Color.WHITE);
        addressField.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        addressField.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        JLabel birthDateLabel = new JLabel("Birth Date (yyyy-MM-dd):");
        birthDateLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JTextField birthDateField = new JTextField(user.getBirthDate() != null ? user.getBirthDate().format(DateTimeFormatter.ofPattern("yyyy-MM-dd")) : "", 20);
        birthDateField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        birthDateField.setEnabled(true);
        birthDateField.setBackground(Color.WHITE);
        birthDateField.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        birthDateField.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        JLabel identityNumberLabel = new JLabel("Identity Number:");
        identityNumberLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));
        JTextField identityNumberField = new JTextField(user.getIdentityNumber() != null ? user.getIdentityNumber() : "", 20);
        identityNumberField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(173, 216, 230), 1),
            BorderFactory.createEmptyBorder(2, 2, 2, 2)
        ));
        identityNumberField.setEnabled(true);
        identityNumberField.setBackground(Color.WHITE);
        identityNumberField.setPreferredSize(new Dimension((int) (250 * scaleFactor), (int) (30 * scaleFactor)));
        identityNumberField.setFont(new Font("Segoe UI", Font.PLAIN, (int) (BASE_FONT_SIZE * scaleFactor)));

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 0;
        formPanel.add(emailLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(emailField, gbc);

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 1;
        formPanel.add(fullNameLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(fullNameField, gbc);

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 2;
        formPanel.add(roleLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(roleComboBox, gbc);

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 3;
        formPanel.add(statusLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(statusComboBox, gbc);

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 4;
        formPanel.add(phoneLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(phoneField, gbc);

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 5;
        formPanel.add(addressLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(addressField, gbc);

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 6;
        formPanel.add(birthDateLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(birthDateField, gbc);

        gbc.weightx = 0.3;
        gbc.gridx = 0;
        gbc.gridy = 7;
        formPanel.add(identityNumberLabel, gbc);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        formPanel.add(identityNumberField, gbc);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));

        JButton saveButton = new JButton("Save");
        saveButton.setBackground(new Color(46, 139, 87));
        saveButton.setForeground(Color.BLACK);
        saveButton.setFocusPainted(false);
        saveButton.setFont(new Font("Segoe UI", Font.BOLD, (int) (BASE_FONT_SIZE * scaleFactor)));
        saveButton.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(34, 139, 34), 1),
            BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));

        JButton cancelButton = new JButton("Cancel");
        cancelButton.setBackground(new Color(255, 99, 71));
        cancelButton.setForeground(Color.BLACK);
        cancelButton.setFocusPainted(false);
        cancelButton.setFont(new Font("Segoe UI", Font.BOLD, (int) (BASE_FONT_SIZE * scaleFactor)));
        cancelButton.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(255, 69, 0), 1),
            BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));

        saveButton.addActionListener(e -> {
            String email = emailField.getText().trim();
            String fullName = fullNameField.getText().trim();
            String role = (String) roleComboBox.getSelectedItem();
            String status = (String) statusComboBox.getSelectedItem();
            String phone = phoneField.getText().trim();
            String address = addressField.getText().trim();
            Object birthDateObj = parseDateTime(birthDateField.getText().trim());
            LocalDate birthDate = birthDateObj instanceof LocalDate ? (LocalDate) birthDateObj : null;
            String identityNumber = identityNumberField.getText().trim();

            if (email.isEmpty() || fullName.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, 
                    "Email and Full Name are required", 
                    "Input Error", 
                    JOptionPane.ERROR_MESSAGE);
                return;
            }

            user.setEmail(email);
            user.setFullName(fullName);
            user.setRole(role);
            user.setStatus(status);
            user.setPhone(phone);
            user.setAddress(address);
            user.setBirthDate(birthDate);
            user.setIdentityNumber(identityNumber);
            user.setUpdateDate(LocalDateTime.now());

            updateUser(user);
            dialog.dispose();
        });

        cancelButton.addActionListener(e -> dialog.dispose());

        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);

        dialog.add(formPanel, BorderLayout.CENTER);
        dialog.add(buttonPanel, BorderLayout.SOUTH);

        dialog.setFocusable(true);
        emailField.requestFocusInWindow();
        dialog.setVisible(true);
    }

    private void confirmAndDeleteUser() {
        Task user = getUserFromSelectedRow();
        if (user == null) return;
        
        int option = JOptionPane.showConfirmDialog(
            this,
            "Are you sure you want to delete user: " + user.getFullName() + "?",
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        );
        
        if (option == JOptionPane.YES_OPTION) {
            deleteUser(user.getId());
        }
    }
    
    private void createUser(Task user) {
        SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
            @Override
            protected Boolean doInBackground() {
                return apiService.createUser(user);
            }
            
            @Override
            protected void done() {
                try {
                    boolean success = get();
                    if (success) {
                        refreshUsers();
                        JOptionPane.showMessageDialog(TaskPanel.this, 
                            "User created successfully", 
                            "Success", 
                            JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(TaskPanel.this, 
                            "Failed to create user", 
                            "Error", 
                            JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    JOptionPane.showMessageDialog(TaskPanel.this, 
                        "Error creating user: " + e.getMessage(), 
                        "Error", 
                        JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        
        worker.execute();
    }
    
    public void updateUser(Task user) {
        SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
            @Override
            protected Boolean doInBackground() {
                return apiService.updateUser(user);
            }
            
            @Override
            protected void done() {
                try {
                    boolean success = get();
                    if (success) {
                        refreshUsers();
                        JOptionPane.showMessageDialog(TaskPanel.this, 
                            "User updated successfully", 
                            "Success", 
                            JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(TaskPanel.this, 
                            "Failed to update user", 
                            "Error", 
                            JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    JOptionPane.showMessageDialog(TaskPanel.this, 
                        "Error updating user: " + e.getMessage(), 
                        "Error", 
                        JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        
        worker.execute();
    }
    
    private void deleteUser(Long userId) {
        SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
            @Override
            protected Boolean doInBackground() {
                return apiService.deleteUser(userId);
            }
            
            @Override
            protected void done() {
                try {
                    boolean success = get();
                    if (success) {
                        refreshUsers();
                        JOptionPane.showMessageDialog(TaskPanel.this, 
                            "User deleted successfully", 
                            "Success", 
                            JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(TaskPanel.this, 
                            "Failed to delete user", 
                            "Error", 
                            JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    JOptionPane.showMessageDialog(TaskPanel.this, 
                        "Error deleting user: " + e.getMessage(), 
                        "Error", 
                        JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        
        worker.execute();
    }
}