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

import org.apache.shiro.subject.Subject;

/**
 *
 * @author richter
 */
public interface Authenticator {

    /**
     * Authenticates {@code subject} using the implementation specific
     * mechanism.
     *
     * @param subject
     * @return {@code true} if the authentication was successful, {@code false}
     * otherwise
     * @throws richtercloud.credential.store.AuthenticatorException wraps any
     * exception which might occur
     */
    boolean authenticate(Subject subject) throws AuthenticatorException;

    /**
     * Authenticates {@code subject} using the implementation specific
     * mechanism. Only requests to enter a password for the fixed username.
     *
     * @param subject
     * @param fixedUsername
     * @return {@code true} if the authentication was successful, {@code false}
     * otherwise (including cancelation/abortion of authentication by the user)
     * @throws richtercloud.credential.store.AuthenticatorException wraps any
     * exception which might occur
     */
    boolean authenticate(Subject subject,
            String fixedUsername) throws AuthenticatorException;
}
