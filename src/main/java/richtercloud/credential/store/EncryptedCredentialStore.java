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

/**
 * A {@link CredentialStore} which allows specification of passwords at the
 * moment when credentials are stored.
 *
 * Implementations which use a fixed password set on initialization are possible
 * as well - extend {@link CredentialStore}.
 *
 * @author richter
 */
public interface EncryptedCredentialStore<S, T> extends CredentialStoreBase {

    void store(S subject, T password, String key) throws CredentialException;

    T retrieve(S subject, String key) throws CredentialException;
}
