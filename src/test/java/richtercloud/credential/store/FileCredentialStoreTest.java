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
import org.apache.commons.lang3.RandomStringUtils;
import static org.junit.Assert.*;
import org.junit.Test;

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
        int subjectLength = TestTools.RANDOM.nextInt(1024*1024)+1;
        assert subjectLength > 0;
        String subject = RandomStringUtils.random(subjectLength);
        int passwordLength = TestTools.RANDOM.nextInt(1024*1024)+1;
        String password = RandomStringUtils.random(passwordLength);
        File file = File.createTempFile(FileCredentialStoreTest.class.getSimpleName(), null);
        file.delete();
        FileCredentialStore<String, String> instance = new FileCredentialStore<>(file);
        instance.init();
        instance.store(subject, password);
        String result = instance.retrieve(subject);
        String expResult = password;
        assertEquals(expResult, result);
        //test consecutive calls to retrieve reveal the same result
        result = instance.retrieve(subject);
        assertEquals(expResult, result);
        //overwrite credential
        int password2Length = TestTools.RANDOM.nextInt(1024*1024)+1;
        String password2 = RandomStringUtils.random(password2Length);
        instance.store(subject, password2);
        result = instance.retrieve(subject);
        expResult = password2;
        assertEquals(expResult, result);
    }
}
