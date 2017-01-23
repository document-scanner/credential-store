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

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;

/**
 *
 * @author richter
 */
public class EncryptedFileCredentialStore extends FileCredentialStore {

    public EncryptedFileCredentialStore(File file) {
        super(file);
    }

    /**
     *
     * @param subject the {@link subject} to use for mapping
     * @param password the password to store
     * @throws CredentialException wraps any exception which might occur
     * @throws IllegalArgumentException if {@code username}'s principal isn't
     * set
     */
    @Override
    public void store(Subject subject, String password) throws CredentialException {
        if ( !subject.isAuthenticated() ) {
            throw new IllegalStateException(String.format("user '%s' isn't "
                    + "authenticated", subject));
        }
        String key = getSubjectPassword(subject);
        try {
            String password0 = Encryptor.encrypt(key, password);
            super.store(subject, password0);
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException | InvalidParameterSpecException ex) {
            throw new CredentialException(ex);
        }
    }

    @Override
    public String retrieve(Subject subject) throws CredentialException {
        if ( !subject.isAuthenticated() ) {
            throw new IllegalStateException(String.format("user '%s' isn't "
                    + "authenticated", subject));
        }
        String password0 = super.retrieve(subject);
        if(password0 == null) {
            return null;
        }
        String key = getSubjectPassword(subject);
        try {
            String retValue = Encryptor.decrypt(key,
                    password0);
            return retValue;
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException | InvalidAlgorithmParameterException | InvalidKeySpecException | InvalidParameterSpecException ex) {
            throw new CredentialException(ex);
        }
    }

    private String getSubjectPassword(Subject subject) {
        Object tokenObject = subject.getSession().getAttribute(DialogAuthenticator.TOKEN_KEY);
        if(tokenObject == null) {
            throw new IllegalArgumentException(String.format("subject's "
                    + "session is expected to have attribute '%s' to be set",
                    DialogAuthenticator.TOKEN_KEY));
        }
        if(!(tokenObject instanceof UsernamePasswordToken)) {
            throw new IllegalStateException(String.format("subject's "
                    + "session attribute '%s' is expected to be of type %s",
                    DialogAuthenticator.TOKEN_KEY,
                    UsernamePasswordToken.class.getName()));
        }
        UsernamePasswordToken token = (UsernamePasswordToken) tokenObject;
        String retValue = new String(token.getPassword());
        return retValue;
    }
}
