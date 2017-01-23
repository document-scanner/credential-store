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

import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;

/**
 *
 * @author richter
 */
public class DialogAuthenticator implements Authenticator {
    public final static String TOKEN_KEY = "token";

    @Override
    public boolean authenticate(Subject username) {
        AuthenticationDialog dialog = new AuthenticationDialog(null //parent
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
        username.login(token);
        username.getSession().setAttribute(TOKEN_KEY, token);
        return true;
    }
}
