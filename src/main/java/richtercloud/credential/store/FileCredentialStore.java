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
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.apache.shiro.subject.Subject;

/**
 * A {@link CredentialStore} using file with plain text storage which might be a
 * security risk.
 *
 * @author richter
 * @param <T> the type which contains the credentials data
 */
/*
internal implementation notes:
- Subject can't be used for storage keys because it doesn't override equals and
hashCode
*/
public class FileCredentialStore<T> implements CredentialStore<T> {
    private final File file;

    public FileCredentialStore(File file) {
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
    public void store(Subject subject, T password) throws CredentialException {
        if(subject.getPrincipal() == null) {
            throw new IllegalArgumentException("username's principal mustn't be null");
        }
        XStream xStream = new XStream();
        Map<Object, T> store;
        if(!file.exists()) {
            store = new HashMap<>();
        }else {
            store = (Map<Object, T>) xStream.fromXML(file);
        }
        store.put(subject.getPrincipal(), password);
        try {
            xStream.toXML(store, new FileOutputStream(file));
        } catch (IOException ex) {
            throw new CredentialException(ex);
        }
    }

    @Override
    public T retrieve(Subject subject) throws CredentialException {
        if(subject.getPrincipal() == null) {
            throw new IllegalArgumentException("username's principal mustn't be null");
        }
        XStream xStream = new XStream();
        Map<Object, T> store;
        if(!file.exists()) {
            store = new HashMap<>();
        }else {
            store = (Map<Object, T>) xStream.fromXML(file);
        }
        T retValue = store.get(subject.getPrincipal());
        return retValue;
    }
}
