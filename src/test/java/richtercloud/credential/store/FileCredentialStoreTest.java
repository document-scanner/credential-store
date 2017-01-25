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
import org.apache.shiro.subject.Subject;
import static org.junit.Assert.*;
import org.junit.Test;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 *
 * @author richter
 */
public class FileCredentialStoreTest {

    /**
     * Test of store method, of class FileCredentialStore.
     */
    @Test
    public void testStoreAndRetrieve() throws Exception {
        Subject subject = mock(Subject.class);
        String username = "username";
        when(subject.getPrincipal()).thenReturn(username);
            //working with SecurityUtils.getCurrentUser doesn't allow setting of
            //principal
        String password = "password";
        File file = File.createTempFile(FileCredentialStoreTest.class.getSimpleName(), null);
        file.delete();
        FileCredentialStore<String> instance = new FileCredentialStore<>(file);
        instance.init();
        instance.store(subject, password);
        String result = instance.retrieve(subject);
        String expResult = password;
        assertEquals(expResult, result);
        //test consecutive calls to retrieve reveal the same result
        result = instance.retrieve(subject);
        assertEquals(expResult, result);
        //overwrite credential
        String password2 = "password2";
        instance.store(subject, password2);
        result = instance.retrieve(subject);
        expResult = password2;
        assertEquals(expResult, result);
    }
}
