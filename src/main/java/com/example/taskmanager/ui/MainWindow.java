package com.example.taskmanager.ui;

import com.example.taskmanager.service.ApiService;
import com.example.taskmanager.service.AuthService;
import com.google.api.services.oauth2.model.Userinfo;
import com.example.taskmanager.auth.GoogleLoginHelper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.swing.*;
import javax.swing.plaf.basic.BasicButtonUI;
import java.awt.*;
import java.awt.event.*;
import java.awt.geom.RoundRectangle2D;
import javax.imageio.ImageIO;

public class MainWindow extends JFrame {
    
    private static final Color PRIMARY_COLOR = new Color(79, 70, 229); // Indigo color like in your web design
    private static final Color BACKGROUND_COLOR = new Color(250, 250, 252);
    private static final Color TEXT_COLOR = new Color(71, 85, 105);
    private static Font MAIN_FONT = new Font("Segoe UI", Font.PLAIN, 14);
    private static Font WELCOME_FONT = new Font("Segoe UI", Font.BOLD, 24);
    private static final String WEB_APP_URL = "http://localhost:80/customer"; // URL của ứng dụng web
    
    // Lưu trữ font size gốc
    private static final int MAIN_FONT_SIZE = 14;
    private static final int WELCOME_FONT_SIZE = 24;
    private static final int TITLE_BAR_FONT_SIZE = 20;
    private static final int FOOTER_FONT_SIZE = 12;
    
    // Services
    private final AuthService authService;
    private final ApiService apiService;
    
    // Layout
    private final CardLayout cardLayout;
    private final JPanel contentPanel;
    
    // Panels
    private final TaskPanel taskPanel;
    
    // Components để cập nhật font
    private JLabel welcomeLabel;
    private JLabel subtitleLabel;
    private JButton googleLoginButton;
    private JLabel footerLabel;
    private JButton minimizeButton;
    private JButton maximizeButton;
    private JButton closeButton;
    
    // Constants
    private static final String LOGIN_PANEL = "LOGIN";
    private static final String TASK_PANEL = "TASKS";
    
    // Trạng thái phóng to/thu nhỏ
    private boolean isMaximized = false;
    private String currentPanel = LOGIN_PANEL; // Theo dõi panel hiện tại
    private double scaleFactor = 1.0; // Tỷ lệ phóng to font

    public MainWindow() {
        // Khởi tạo services
        this.authService = new AuthService();
        this.apiService = new ApiService(this.authService);
        
        setTitle("Task Manager");
        setSize(400, 500);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setUndecorated(true); // Remove default window border
        setShape(new RoundRectangle2D.Double(0, 0, 400, 500, 15, 15)); // Rounded corners
        
        // Sử dụng CardLayout để chuyển đổi giữa các panel
        this.cardLayout = new CardLayout();
        this.contentPanel = new JPanel(cardLayout);
        
        // Panel chính với hiệu ứng bóng đổ
        JPanel mainPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                
                // Paint background
                g2.setColor(BACKGROUND_COLOR);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 15, 15);
                
                // Shadow effect (top border)
                g2.setColor(new Color(0, 0, 0, 15));
                g2.drawRoundRect(0, 0, getWidth()-1, getHeight()-1, 15, 15);
                
                g2.dispose();
            }
        };
        mainPanel.setLayout(new BorderLayout(0, 20));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(30, 40, 30, 40));
        mainPanel.setBackground(BACKGROUND_COLOR);
        
        // Custom title bar
        JPanel titleBar = createTitleBar();
        mainPanel.add(titleBar, BorderLayout.NORTH);
        
        // Tạo modern login panel
        JPanel modernLoginPanel = createModernLoginPanel();
        
        // Tạo panel nhiệm vụ
        this.taskPanel = new TaskPanel(apiService, authService, this);
        
        // Thêm các panel vào CardLayout
        contentPanel.add(modernLoginPanel, LOGIN_PANEL);
        contentPanel.add(taskPanel, TASK_PANEL);
        
        mainPanel.add(contentPanel, BorderLayout.CENTER);
        add(mainPanel);
        
        // Make the window draggable
        addWindowDragListener();
    }
    
    private JPanel createTitleBar() {
        JPanel titleBar = new JPanel();
        titleBar.setLayout(new BorderLayout());
        titleBar.setOpaque(false);
        
        // Panel chứa các nút điều khiển (minimize, maximize/restore, close)
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        controlPanel.setOpaque(false);

        // Nút Minimize
        minimizeButton = new JButton("–");
        minimizeButton.setForeground(TEXT_COLOR);
        minimizeButton.setBorderPainted(false);
        minimizeButton.setContentAreaFilled(false);
        minimizeButton.setFocusPainted(false);
        minimizeButton.setFont(new Font("Arial", Font.BOLD, TITLE_BAR_FONT_SIZE));
        minimizeButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        minimizeButton.addActionListener(e -> setState(Frame.ICONIFIED)); // Thu nhỏ cửa sổ
        
        // Nút Maximize/Restore
        maximizeButton = new JButton("□");
        maximizeButton.setForeground(TEXT_COLOR);
        maximizeButton.setBorderPainted(false);
        maximizeButton.setContentAreaFilled(false);
        maximizeButton.setFocusPainted(false);
        maximizeButton.setFont(new Font("Arial", Font.BOLD, TITLE_BAR_FONT_SIZE));
        maximizeButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        maximizeButton.addActionListener(e -> toggleMaximizeRestore());

        // Nút Close
        closeButton = new JButton("×");
        closeButton.setForeground(TEXT_COLOR);
        closeButton.setBorderPainted(false);
        closeButton.setContentAreaFilled(false);
        closeButton.setFocusPainted(false);
        closeButton.setFont(new Font("Arial", Font.BOLD, TITLE_BAR_FONT_SIZE));
        closeButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        closeButton.addActionListener(e -> {
            authService.logout(); // Đảm bảo logout khi đóng ứng dụng
            System.exit(0);
        });
        
        // Thêm các nút vào panel điều khiển
        controlPanel.add(minimizeButton);
        controlPanel.add(maximizeButton);
        controlPanel.add(closeButton);
        
        titleBar.add(controlPanel, BorderLayout.EAST);
        return titleBar;
    }

    private void toggleMaximizeRestore() {
        if (isMaximized) {
            // Khôi phục kích thước bình thường
            setExtendedState(Frame.NORMAL);
            maximizeButton.setText("□"); // Biểu tượng khi ở trạng thái bình thường
            scaleFactor = 1.0; // Đặt lại tỷ lệ phóng to
            
            // Điều chỉnh kích thước và góc bo tròn dựa trên panel hiện tại
            if (currentPanel.equals(TASK_PANEL)) {
                setSize(1100, 750);
                setShape(null); // TaskPanel không có góc bo tròn theo thiết kế hiện tại
                // Nếu muốn TaskPanel có góc bo tròn, uncomment dòng dưới
                // setShape(new RoundRectangle2D.Double(0, 0, getWidth(), getHeight(), 15, 15));
            } else {
                setSize(400, 500);
                setShape(new RoundRectangle2D.Double(0, 0, getWidth(), getHeight(), 15, 15));
            }
            setLocationRelativeTo(null);
        } else {
            // Phóng to toàn màn hình
            setExtendedState(Frame.MAXIMIZED_BOTH);
            maximizeButton.setText("❐"); // Biểu tượng khi phóng to
            setShape(null); // Bỏ góc bo tròn khi phóng to
            
            // Tính tỷ lệ phóng to dựa trên kích thước màn hình
            Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
            Dimension originalSize = currentPanel.equals(TASK_PANEL) ? new Dimension(1100, 750) : new Dimension(400, 500);
            scaleFactor = Math.min(screenSize.getWidth() / originalSize.getWidth(), screenSize.getHeight() / originalSize.getHeight());
        }
        isMaximized = !isMaximized;
        
        // Cập nhật font size
        updateFonts();
        taskPanel.updateFonts(scaleFactor); // Cập nhật font trong TaskPanel
    }

    private void updateFonts() {
        // Cập nhật font cho các thành phần trong MainWindow
        MAIN_FONT = new Font("Segoe UI", Font.PLAIN, (int) (MAIN_FONT_SIZE * scaleFactor));
        WELCOME_FONT = new Font("Segoe UI", Font.BOLD, (int) (WELCOME_FONT_SIZE * scaleFactor));
        Font titleBarFont = new Font("Arial", Font.BOLD, (int) (TITLE_BAR_FONT_SIZE * scaleFactor));
        Font footerFont = new Font("Segoe UI", Font.PLAIN, (int) (FOOTER_FONT_SIZE * scaleFactor));
        
        if (welcomeLabel != null) {
            welcomeLabel.setFont(WELCOME_FONT);
        }
        if (subtitleLabel != null) {
            subtitleLabel.setFont(MAIN_FONT);
        }
        if (googleLoginButton != null) {
            googleLoginButton.setFont(new Font("Segoe UI", Font.BOLD, (int) (14 * scaleFactor)));
        }
        if (footerLabel != null) {
            footerLabel.setFont(footerFont);
        }
        if (minimizeButton != null) {
            minimizeButton.setFont(titleBarFont);
        }
        if (maximizeButton != null) {
            maximizeButton.setFont(titleBarFont);
        }
        if (closeButton != null) {
            closeButton.setFont(titleBarFont);
        }
    }
    
    private JLabel createLogoLabel() {
        JLabel logoLabel = new JLabel();
        try {
            // Use a placeholder logo (you should replace this with your actual logo)
            ImageIcon icon = new ImageIcon(getClass().getResource("/com/example/taskmanager/resources/logo.png"));
            Image img = icon.getImage().getScaledInstance((int) (120 * scaleFactor), (int) (120 * scaleFactor), Image.SCALE_SMOOTH);
            logoLabel.setIcon(new ImageIcon(img));
        } catch (Exception e) {
            // If logo not found, use text instead
            logoLabel.setText("TASK MANAGER");
            logoLabel.setFont(new Font("Segoe UI", Font.BOLD, (int) (18 * scaleFactor)));
            logoLabel.setForeground(PRIMARY_COLOR);
        }
        return logoLabel;
    }
    
    private JButton createGoogleLoginButton() {
        googleLoginButton = new JButton("Đăng nhập bằng Google");
        googleLoginButton.setFont(new Font("Segoe UI", Font.BOLD, (int) (14 * scaleFactor)));
        googleLoginButton.setForeground(Color.BLACK);
        googleLoginButton.setBackground(Color.WHITE);
        googleLoginButton.setFocusPainted(false);
        googleLoginButton.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(226, 232, 240), 1, true),
            BorderFactory.createEmptyBorder(10, 15, 10, 15)
        ));
        googleLoginButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        
        // Try to load Google icon
        try {
            ImageIcon googleIcon = new ImageIcon(getClass().getResource("/com/example/taskmanager/resources/google.png"));
            Image img = googleIcon.getImage().getScaledInstance((int) (20 * scaleFactor), (int) (20 * scaleFactor), Image.SCALE_SMOOTH);
            googleLoginButton.setIcon(new ImageIcon(img));
            googleLoginButton.setIconTextGap(10);
        } catch (Exception e) {
            // If icon not found, continue without it
            System.out.println("Google icon not found");
        }
        
        // Custom button UI
        googleLoginButton.setUI(new BasicButtonUI() {
            @Override
            public void paint(Graphics g, JComponent c) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                
                AbstractButton b = (AbstractButton) c;
                ButtonModel model = b.getModel();
                
                // Paint button background
                if (model.isPressed()) {
                    g2.setColor(new Color(241, 245, 249));
                } else if (model.isRollover()) {
                    g2.setColor(new Color(248, 250, 252));
                } else {
                    g2.setColor(Color.WHITE);
                }
                
                g2.fillRoundRect(0, 0, c.getWidth(), c.getHeight(), 8, 8);
                
                // Paint button border
                g2.setColor(new Color(226, 232, 240));
                g2.drawRoundRect(0, 0, c.getWidth()-1, c.getHeight()-1, 8, 8);
                
                // Paint text and icon
                super.paint(g2, c);
                g2.dispose();
            }
        });
        
        // Hover effect
        googleLoginButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                googleLoginButton.setBackground(new Color(248, 250, 252));
            }
            
            @Override
            public void mouseExited(MouseEvent e) {
                googleLoginButton.setBackground(Color.WHITE);
            }
        });
        
        // Add action - sử dụng GoogleLoginHelper thật
        googleLoginButton.addActionListener(this::handleGoogleLogin);
        
        return googleLoginButton;
    }
    
//    private void handleGoogleLogin(ActionEvent e) {
//        JButton googleLoginButton = (JButton)e.getSource();
//        googleLoginButton.setEnabled(false);
//        googleLoginButton.setText("Đang đăng nhập...");
//        
//        SwingWorker<Userinfo, Void> worker = new SwingWorker<>() {
//            @Override
//            protected Userinfo doInBackground() throws Exception {
//                return GoogleLoginHelper.login();
//            }
//            
//            @Override
//            protected void done() {
//                try {
//                    Userinfo userInfo = get();
//                    if (userInfo != null) {
//                        boolean success = authService.loginWithGoogle(userInfo);
//                        if (success) {
//                            // Kiểm tra role
//                            String userRole = authService.getLastLoginRole();
//                            String userEmail = userInfo.getEmail();
//                            if (userRole == null || !userRole.equals("admin")) {
//                                String errorMessage = "Bạn chưa được cấp quyền để truy cập ứng dụng này.\n";
//                                if (userRole != null && userRole.equals("customer")) {
//                                    errorMessage += "Vui lòng truy cập ứng dụng web tại: " + WEB_APP_URL;
//                                } else {
//                                    errorMessage += "Tài khoản của bạn (" + userEmail + ") không có quyền truy cập.";
//                                }
//                                JOptionPane.showMessageDialog(MainWindow.this, 
//                                    errorMessage, 
//                                    "Access Denied", 
//                                    JOptionPane.ERROR_MESSAGE);
//                                authService.logout();
//                            } else {
//                                // Role là admin, chuyển sang TaskPanel
//                                JOptionPane.showMessageDialog(MainWindow.this, 
//                                    "Xin chào " + userInfo.getName() + "\nEmail: " + userInfo.getEmail(), 
//                                    "Đăng nhập thành công", 
//                                    JOptionPane.INFORMATION_MESSAGE);
//                                showTaskPanel();
//                            }
//                        } else {
//                            JOptionPane.showMessageDialog(MainWindow.this, 
//                                "Không thể đăng nhập với tài khoản Google này", 
//                                "Lỗi đăng nhập", 
//                                JOptionPane.ERROR_MESSAGE);
//                            authService.logout();
//                        }
//                    } else {
//                        JOptionPane.showMessageDialog(MainWindow.this, 
//                            "Đăng nhập Google thất bại", 
//                            "Lỗi đăng nhập", 
//                            JOptionPane.ERROR_MESSAGE);
//                        authService.logout();
//                    }
//                } catch (Exception ex) {
//                    ex.printStackTrace();
//                    JOptionPane.showMessageDialog(MainWindow.this, 
//                        "Lỗi đăng nhập Google: " + ex.getMessage(), 
//                        "Lỗi đăng nhập", 
//                        JOptionPane.ERROR_MESSAGE);
//                    authService.logout();
//                } finally {
//                    googleLoginButton.setEnabled(true);
//                    googleLoginButton.setText("Đăng nhập bằng Google");
//                }
//            }
//        };
//        worker.execute();
//    }
    private void handleGoogleLogin(ActionEvent e) {
        JButton googleLoginButton = (JButton)e.getSource();
        googleLoginButton.setEnabled(false);
        googleLoginButton.setText("Đang đăng nhập...");
        
        SwingWorker<Userinfo, Void> worker = new SwingWorker<>() {
            @Override
            protected Userinfo doInBackground() throws Exception {
                return GoogleLoginHelper.login();
            }
            
            @Override
            protected void done() {
                try {
                    Userinfo userInfo = get();
                    if (userInfo != null) {
                        boolean success = authService.loginWithGoogle(userInfo);
                        if (success) {
                            // Lấy role và status từ response
                            String userRole = authService.getLastLoginRole();
                            String userStatus = null; // Cần lấy status từ response
                            // Giả sử response từ /app_login trả về status trong JSON
                            String responseBody = authService.getLastLoginResponse(); // Cần thêm phương thức này
                            if (responseBody != null) {
                                JsonNode jsonNode = new ObjectMapper().readTree(responseBody);
                                userStatus = jsonNode.has("status") ? jsonNode.get("status").asText() : null;
                            }

                            String userEmail = userInfo.getEmail();
                            if (userRole != null && userRole.equals("admin") && userStatus != null && userStatus.equals("Active")) {
                                // Role là admin và status là Active, chuyển sang TaskPanel
                                JOptionPane.showMessageDialog(MainWindow.this, 
                                    "Xin chào " + userInfo.getName() + "\nEmail: " + userInfo.getEmail(), 
                                    "Đăng nhập thành công", 
                                    JOptionPane.INFORMATION_MESSAGE);
                                showTaskPanel();
                            } else {
                                String errorMessage = "Bạn chưa được cấp quyền để truy cập ứng dụng này.\n";
                                if (userRole != null && userRole.equals("customer")) {
                                    errorMessage += "Vui lòng truy cập ứng dụng web tại: " + WEB_APP_URL;
                                } else if (userStatus != null && userStatus.equals("Blocked")) {
                                    errorMessage += "Tài khoản của bạn (" + userEmail + ") đã bị chặn.";
                                } else {
                                    errorMessage += "Tài khoản của bạn (" + userEmail + ") không có quyền admin hoặc không Active.";
                                }
                                JOptionPane.showMessageDialog(MainWindow.this, 
                                    errorMessage, 
                                    "Access Denied", 
                                    JOptionPane.ERROR_MESSAGE);
                                authService.logout();
                            }
                        } else {
                            JOptionPane.showMessageDialog(MainWindow.this, 
                                "Không thể đăng nhập với tài khoản Google này", 
                                "Lỗi đăng nhập", 
                                JOptionPane.ERROR_MESSAGE);
                            authService.logout();
                        }
                    } else {
                        JOptionPane.showMessageDialog(MainWindow.this, 
                            "Đăng nhập Google thất bại", 
                            "Lỗi đăng nhập", 
                            JOptionPane.ERROR_MESSAGE);
                        authService.logout();
                    }
                } catch (Exception ex) {
                    ex.printStackTrace();
                    JOptionPane.showMessageDialog(MainWindow.this, 
                        "Lỗi đăng nhập Google: " + ex.getMessage(), 
                        "Lỗi đăng nhập", 
                        JOptionPane.ERROR_MESSAGE);
                    authService.logout();
                } finally {
                    googleLoginButton.setEnabled(true);
                    googleLoginButton.setText("Đăng nhập bằng Google");
                }
            }
        };
        worker.execute();
    }
    
    private void addWindowDragListener() {
        final Point dragPoint = new Point();
        
        addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                dragPoint.x = e.getX();
                dragPoint.y = e.getY();
            }
        });
        
        addMouseMotionListener(new MouseMotionAdapter() {
            @Override
            public void mouseDragged(MouseEvent e) {
                Point location = getLocation();
                setLocation(location.x + e.getX() - dragPoint.x,
                            location.y + e.getY() - dragPoint.y);
            }
        });
    }
    
    private JPanel createModernLoginPanel() {
        // Center panel for login components
        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.Y_AXIS));
        centerPanel.setOpaque(false);
        
        // Logo
        JLabel logoLabel = createLogoLabel();
        logoLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        centerPanel.add(logoLabel);
        centerPanel.add(Box.createVerticalStrut(30));
        
        // Welcome text
        welcomeLabel = new JLabel("Welcome!");
        welcomeLabel.setFont(WELCOME_FONT);
        welcomeLabel.setForeground(new Color(30, 41, 59));
        welcomeLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        centerPanel.add(welcomeLabel);
        
        subtitleLabel = new JLabel("Please login using your Google account.");
        subtitleLabel.setFont(MAIN_FONT);
        subtitleLabel.setForeground(TEXT_COLOR);
        subtitleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        centerPanel.add(subtitleLabel);
        centerPanel.add(Box.createVerticalStrut(40));
        
        // Google Login button
        googleLoginButton = createGoogleLoginButton();
        googleLoginButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        centerPanel.add(googleLoginButton);
        centerPanel.add(Box.createVerticalStrut(30));
        
        // Footer text
        footerLabel = new JLabel("Only Google login is supported.");
        footerLabel.setFont(new Font("Segoe UI", Font.PLAIN, (int) (FOOTER_FONT_SIZE * scaleFactor)));
        footerLabel.setForeground(new Color(148, 163, 184));
        footerLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        centerPanel.add(footerLabel);
        
        return centerPanel;
    }
    
    public void showLoginPanel() {
        cardLayout.show(contentPanel, LOGIN_PANEL);
        currentPanel = LOGIN_PANEL;
        
        // Điều chỉnh kích thước và góc bo tròn nếu không ở trạng thái phóng to
        if (!isMaximized) {
            setSize(400, 500);
            setShape(new RoundRectangle2D.Double(0, 0, getWidth(), getHeight(), 15, 15));
            setLocationRelativeTo(null);
        }
        updateFonts();
    }
    
    public void showTaskPanel() {
        cardLayout.show(contentPanel, TASK_PANEL);
        currentPanel = TASK_PANEL;
        
        // Điều chỉnh kích thước và góc bo tròn nếu không ở trạng thái phóng to
        if (!isMaximized) {
            setSize(1100, 750);
            setShape(null); // TaskPanel không có góc bo tròn theo thiết kế hiện tại
            // Nếu muốn TaskPanel có góc bo tròn, uncomment dòng dưới
            // setShape(new RoundRectangle2D.Double(0, 0, getWidth(), getHeight(), 15, 15));
            setLocationRelativeTo(null);
        }
        // Refresh tasks khi hiển thị panel
        taskPanel.refreshUsers();
        taskPanel.updateFonts(scaleFactor);
    }
    
    // Main method for testing
    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        SwingUtilities.invokeLater(() -> {
            MainWindow mainWindow = new MainWindow();
            mainWindow.setVisible(true);
        });
    }
}