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
public class Tools {

    public static void validateSubject(Object subject) {
        if(subject == null) {
            throw new IllegalArgumentException("subject mustn't be null");
        }
    }

    public static void validatePassword(Object password) {
        if(password == null) {
            throw new IllegalArgumentException("password mustn't be null");
        }
    }

    public static void validateKey(String key) {
        if(key == null) {
            throw new IllegalArgumentException("key mustn't be null");
        }
        if(key.isEmpty()) {
            throw new IllegalArgumentException("key mustn't be empty");
        }
    }

    private Tools() {
    }
}
