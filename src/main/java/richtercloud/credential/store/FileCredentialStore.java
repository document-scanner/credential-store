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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * A {@link CredentialStore} using file with plain text storage which might be a
 * security risk.
 *
 * @author richter
 * @param <S> the type of subject to store credentials for
 * @param <T> the type which contains the credentials data
 */
/*
internal implementation notes:
- Subject can't be used for storage keys because it doesn't override equals and
hashCode
*/
public class FileCredentialStore<S, T> implements CredentialStore<S, T> {
    private final static XStream X_STREAM = new XStream();
    private final File file;

    public FileCredentialStore(File file) {
        if(file == null) {
            throw new IllegalArgumentException("file mustn't be null");
        }
        this.file = file;
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
    public void store(S subject, T password) throws CredentialException {
        if(!isInit()) {
            throw new IllegalStateException("store hasn't been initialized");
        }
        Tools.validateSubject(subject);
        Tools.validatePassword(password);
        XStream xStream = new XStream();
        Map<Object, T> store;
        if(!file.exists()) {
            store = new HashMap<>();
        }else {
            store = (Map<Object, T>) xStream.fromXML(file);
        }
        store.put(subject, password);
        try {
            xStream.toXML(store, new FileOutputStream(file));
        } catch (IOException ex) {
            throw new CredentialException(ex);
        }
    }

    @Override
    public T retrieve(S subject) throws CredentialException {
        if(!isInit()) {
            throw new IllegalStateException("store hasn't been initialized");
        }
        Tools.validateSubject(subject);
        Map<Object, T> store;
        if(!file.exists()) {
            store = new HashMap<>();
        }else {
            store = (Map<Object, T>) X_STREAM.fromXML(file);
        }
        T retValue = store.get(subject);
        return retValue;
    }

    @Override
    public boolean isInit() {
        try {
            X_STREAM.fromXML(file);
            return true;
        }catch(Exception ex) {
            return false;
        }
    }

    /**
     * Initializes the store.
     *
     * @throws CredentialException wraps any exception
     * @throws IllegalStateException if the store is already initialized
     */
    @Override
    public void init() throws CredentialException {
        if(isInit()) {
            throw new IllegalStateException("store is already initialized");
        }
        try {
            X_STREAM.toXML(new HashMap<>(), new FileOutputStream(file));
        } catch (FileNotFoundException ex) {
            throw new CredentialException(ex);
        }
    }
}
