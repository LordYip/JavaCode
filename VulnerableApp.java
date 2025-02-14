import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

public class VulnerableApp {

    public static void main(String[] args) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Enter username: ");
            String username = reader.readLine();
            System.out.print("Enter password: ");
            String password = reader.readLine();

            if (authenticateUser(username, password)) {
                System.out.println("Login successful!");
            } else {
                System.out.println("Login failed!");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 🚨 CWE-200: Hardcoded Credentials (Sensitive Information Exposure)
    private static boolean authenticateUser(String user, String pass) {
        String hardcodedUser = "admin"; // 🚨 Hardcoded credentials
        String hardcodedPass = "password123"; 

        if (user.equals(hardcodedUser) && pass.equals(hardcodedPass)) {
            return true;
        }
        return checkDatabase(user, pass);
    }

    // 🚨 CWE-89: SQL Injection
    private static boolean checkDatabase(String user, String pass) {
        boolean isAuthenticated = false;
        try {
            // 🚨 Hardcoded database credentials (CWE-200)
            String url = "jdbc:mysql://localhost:3306/users";
            String dbUser = "root";
            String dbPassword = "rootpass";

            Connection conn = DriverManager.getConnection(url, dbUser, dbPassword);
            Statement stmt = conn.createStatement();

            // 🚨 Unsafe SQL query (CWE-89: SQL Injection)
            String query = "SELECT * FROM users WHERE username = '" + user + "' AND password = '" + pass + "'";
            ResultSet rs = stmt.executeQuery(query);

            if (rs.next()) {
                isAuthenticated = true;
            }

            rs.close();
            stmt.close();
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return isAuthenticated;
    }
}
