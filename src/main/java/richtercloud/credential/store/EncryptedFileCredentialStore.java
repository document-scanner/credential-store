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

import com.thoughtworks.xstream.XStream;
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

/**
 *
 * @author richter
 * @param <S> the type of subject to store credentials for
 * @param <T> the type which contains the credentials data
 */
/*
internal implementation notes:
- using ? pattern here (combining composition and interheritance in order to
allow EncryptedFileCredentialStore's T to be of any type and store serialized
encrypted Strings in it
*/
public class EncryptedFileCredentialStore<S, T> implements EncryptedCredentialStore<S, T> {
    private final static XStream X_STREAM = new XStream();
    private final FileCredentialStore<S, String> internalStore;

    public EncryptedFileCredentialStore(File file) {
        this.internalStore = new FileCredentialStore<>(file);
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
    public void store(S subject,
            T password,
            String key) throws CredentialException {
        //serialize password in order to make it possible to encrypt
        String passwordXML = X_STREAM.toXML(password);
        try {
            String passwordXML0 = Encryptor.encrypt(new String(key), passwordXML);
            internalStore.store(subject, passwordXML0);
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException | InvalidParameterSpecException ex) {
            throw new CredentialException(ex);
        }
    }

    @Override
    public T retrieve(S subject,
            String key) throws CredentialException {
        String passwordXML0 = internalStore.retrieve(subject);
        if(passwordXML0 == null) {
            return null;
        }
        try {
            String password0 = Encryptor.decrypt(key,
                    passwordXML0);
            T retValue = (T) X_STREAM.fromXML(password0);
            return retValue;
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException | InvalidAlgorithmParameterException | InvalidKeySpecException | InvalidParameterSpecException ex) {
            throw new CredentialException(ex);
        }
    }

    @Override
    public boolean isInit() {
        return this.internalStore.isInit();
    }

    /**
     * Initializes the store.
     *
     * @throws CredentialException wraps any exception
     * @throws IllegalStateException if the store is already initialized
     */
    @Override
    public void init() throws CredentialException {
        this.internalStore.init();
    }
}
