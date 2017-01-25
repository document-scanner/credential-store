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
package richtercloud.credential.store.shiro;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import richtercloud.credential.store.AuthenticationDialog;

/**
 *
 * @author richter
 */
public class DialogAuthenticator implements Authenticator {
    public final static String TOKEN_KEY = "token";
    private final String dialogLabelText;

    public DialogAuthenticator(String dialogLabelText) {
        this.dialogLabelText = dialogLabelText;
    }

    @Override
    public boolean authenticate(Subject subject) throws AuthenticatorException {
        return authenticate(subject,
                null //fixedUsername
        );
    }

    @Override
    public boolean authenticate(Subject subject,
            String fixedUsername) throws AuthenticatorException {
        AuthenticationDialog dialog = new AuthenticationDialog(null, //parent
                dialogLabelText,
                fixedUsername
        );
        dialog.setLocationRelativeTo(null //component
        );
        dialog.setVisible(true);
        if(dialog.getUsername() == null) {
            //dialog has been canceled
            return false;
        }
        UsernamePasswordToken token = new UsernamePasswordToken(dialog.getUsername(),
                dialog.getPassword());
        token.setRememberMe(true);
            //no need to ask for the password twice
        try {
            subject.login(token);
        } catch ( UnknownAccountException ex ) {
            throw new AuthenticatorException(ex);
        } catch ( IncorrectCredentialsException ex ) {
            throw new AuthenticatorException(ex);
        } catch ( LockedAccountException ex ) {
            throw new AuthenticatorException(ex);
        } catch ( AuthenticationException ex ) {
            throw new AuthenticatorException(ex);
        }
        subject.getSession().setAttribute(TOKEN_KEY, token);
        return true;
    }
}
