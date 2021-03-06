/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package richtercloud.credential.store;

import java.awt.Window;
import javax.swing.JDialog;
import javax.swing.JOptionPane;
import richtercloud.message.handler.Message;
import richtercloud.message.handler.MessageHandler;

/**
 * Provides GUI components to enter a username and password which can be
 * retrieved after the dialog has been closed. It allows to configure the label
 * which explains which credentials to enter and for what and allows to make
 * the username text field read-only in case only a password ought to be
 * required.
 *
 * When the user clicks OK and username (logical) or password are empty a
 * message is displayed to the user and closing denied. This dialog can still be
 * canceled using the Cancel button.
 *
 * @author richter
 */
public class AuthenticationDialog extends JDialog {
    private static final long serialVersionUID = 1L;
    public final static String LABEL_TEXT_DEFAULT = "Please enter credentials:";
    /**
     * The username entered in the username text field. {@code null} indicates
     * that the dialog has been canceled.
     */
    private String username = null;
    /**
     * The password entered in the password field. {@code null} indicates that
     * the dialog has been canceled.
     */
    private char[] password = null;
    private final MessageHandler messageHandler;

    /**
     * Creates new form DialogAuthenticator
     * @param parent the parent of the dialog (positioning has to be handled by
     * caller)
     * @param labelText the text of the label explaining which credentials to
     * enter and for what
     * @param fixedUsername {@code null} if the username (text field) ought to
     * be editable, a read-only username which is displayed in the text field
     * otherwise
     * @param messageHandler the handler to pass error messages on empty
     * username or password
     */
    public AuthenticationDialog(Window parent,
            String labelText,
            String fixedUsername,
            MessageHandler messageHandler) {
        super(parent,
                ModalityType.APPLICATION_MODAL);
        if(messageHandler == null) {
            throw new IllegalArgumentException("messageHandler mustn't be null");
        }
        this.messageHandler = messageHandler;
        initComponents();
        this.label.setText(labelText);
        if(fixedUsername != null) {
            usernameTextField.setText(fixedUsername);
            usernameTextField.setEnabled(false);
        }
    }

    public AuthenticationDialog(Window parent,
            MessageHandler messageHandler) {
        this(parent,
                LABEL_TEXT_DEFAULT,
                null, //fixedUsername
                messageHandler
        );
    }

    public String getUsername() {
        return username;
    }

    public char[] getPassword() {
        return password;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        usernameTextField = new javax.swing.JTextField();
        usernameTextFieldLabel = new javax.swing.JLabel();
        passwordField = new javax.swing.JPasswordField();
        passwordFieldLabel = new javax.swing.JLabel();
        okButton = new javax.swing.JButton();
        cancelButton = new javax.swing.JButton();
        label = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        usernameTextFieldLabel.setText("Username:");

        passwordFieldLabel.setText("Password:");

        okButton.setText("OK");
        okButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButtonActionPerformed(evt);
            }
        });

        cancelButton.setText("Cancel");
        cancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelButtonActionPerformed(evt);
            }
        });

        label.setText("Please enter credentials:");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(label, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(usernameTextFieldLabel)
                            .addComponent(passwordFieldLabel))
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(passwordField, javax.swing.GroupLayout.DEFAULT_SIZE, 277, Short.MAX_VALUE)
                            .addComponent(usernameTextField)))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(cancelButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(okButton)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(label, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(usernameTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(usernameTextFieldLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(passwordField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(passwordFieldLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(okButton)
                    .addComponent(cancelButton))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelButtonActionPerformed
        setVisible(false);
    }//GEN-LAST:event_cancelButtonActionPerformed

    private void okButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButtonActionPerformed
        String username0 = usernameTextField.getText();
        assert username0 != null;
        if(username0.isEmpty()) {
            messageHandler.handle(new Message("Username mustn't be empty", JOptionPane.ERROR_MESSAGE, "Username mustn't be empty"));
            return;
        }
        char[] password0 = passwordField.getPassword();
        assert password0 != null;
        if(password0.length == 0) {
            messageHandler.handle(new Message("Password mustn't be empty", JOptionPane.ERROR_MESSAGE, "Password mustn't be empty"));
            return;
        }
        this.username = usernameTextField.getText();
        this.password = passwordField.getPassword();
        setVisible(false);
    }//GEN-LAST:event_okButtonActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton cancelButton;
    private javax.swing.JLabel label;
    private javax.swing.JButton okButton;
    private javax.swing.JPasswordField passwordField;
    private javax.swing.JLabel passwordFieldLabel;
    private javax.swing.JTextField usernameTextField;
    private javax.swing.JLabel usernameTextFieldLabel;
    // End of variables declaration//GEN-END:variables

}
