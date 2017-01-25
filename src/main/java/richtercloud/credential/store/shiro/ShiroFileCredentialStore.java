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

import java.io.File;
import org.apache.shiro.subject.Subject;
import richtercloud.credential.store.CredentialException;
import richtercloud.credential.store.CredentialStore;
import richtercloud.credential.store.FileCredentialStore;

/**
 *
 * @author richter
 */
public class ShiroFileCredentialStore<T> implements CredentialStore<Subject, T> {
    private final FileCredentialStore<Object, T> internalStore;

    public ShiroFileCredentialStore(File file) {
        this.internalStore = new FileCredentialStore<>(file);
    }

    @Override
    public void store(Subject subject, T password) throws CredentialException {
        if(subject.getPrincipal() == null) {
            throw new IllegalArgumentException("username's principal mustn't be null");
        }
        internalStore.store(subject.getPrincipal(), password);
    }

    @Override
    public T retrieve(Subject subject) throws CredentialException {
        if(subject.getPrincipal() == null) {
            throw new IllegalArgumentException("username's principal mustn't be null");
        }
        return internalStore.retrieve(subject.getPrincipal());
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
