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

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;

/**
 * From http://stackoverflow.com/questions/15554296/simple-java-aes-encrypt-decrypt-example.
 * @author richter
 */
public class Encryptor {
    private final static String SALT_SEPARATOR = ";";

    public static String encrypt(String password, String textToEncrypt) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidParameterSpecException {
        final String salt = KeyGenerators.string().generateKey();
        TextEncryptor encryptor = Encryptors.text(password, salt);
        String encryptedText = encryptor.encrypt(textToEncrypt);
        String retValue = String.format("%s%s%s", salt, SALT_SEPARATOR, encryptedText);
        return retValue;
    }

    public static String decrypt(String password, String encrypted) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, InvalidAlgorithmParameterException, InvalidKeySpecException, InvalidParameterSpecException {
        String salt;
        String encryptedText;
        String[] encryptedSplit = encrypted.split(SALT_SEPARATOR);
        salt = encryptedSplit[0];
        encryptedText = encryptedSplit[1];
        TextEncryptor decryptor = Encryptors.text(password, salt);
            //there's no TextDecryptor, but TextEncryptor.encrypt and
            //TextDecryptor.decrypt
        String decryptedText = decryptor.decrypt(encryptedText);
        return decryptedText;
    }

    private Encryptor() {
    }
}