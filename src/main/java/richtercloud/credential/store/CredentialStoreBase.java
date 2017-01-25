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
 *
 * @author richter
 */
public interface CredentialStoreBase {

    /**
     * Initializes resources used by the pool. Initialization can be delayed
     * until right before usage. The status can be checked with
     * {@link #isInit() }.
     *
     * This is particulary useful if you want to avoid requesting a password
     * input from user when the initilization of a resource still has to occur.
     * In this case it'd be more elegant to request the intialization before
     * requesting input for a password to store the resource.
     * @throws richtercloud.credential.store.CredentialException wraps any
     * exception which might occur
     */
    void init() throws CredentialException;

    boolean isInit();
}
