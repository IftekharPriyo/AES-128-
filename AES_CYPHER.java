import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.File; 
import java.io.FileNotFoundException;  
import java.util.Scanner; 
import java.io.FileWriter;   
import java.io.IOException;  


public class AES_CYPHER {
    
    // initializing keys and formats
    private static final String encryptionKey = "RANDOMKEY1234567";
    private static final String characterEncoding = "UTF-8";
    private static final String cipherTransformation = "AES/CBC/PKCS5PADDING";
    private static final String aesEncryptionAlgorithem = "AES";
    
    
    // encryption library function
    public static String encrypt(String plainText) {
        String encryptedText = "";
        try {
            Cipher cipher   = Cipher.getInstance(cipherTransformation);
            byte[] key      = encryptionKey.getBytes(characterEncoding);
            SecretKeySpec secretKey = new SecretKeySpec(key, aesEncryptionAlgorithem);
            IvParameterSpec ivparameterspec = new IvParameterSpec(key);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivparameterspec);
            byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF8"));
            Base64.Encoder encoder = Base64.getEncoder();
            encryptedText = encoder.encodeToString(cipherText);

        } catch (Exception E) {
             System.err.println("Encrypt Exception : "+E.getMessage());
        }
        return encryptedText;
    }

    
    // decryption library function
    public static String decrypt(String encryptedText) {
        String decryptedText = "";
        try {
            Cipher cipher = Cipher.getInstance(cipherTransformation);
            byte[] key = encryptionKey.getBytes(characterEncoding);
            SecretKeySpec secretKey = new SecretKeySpec(key, aesEncryptionAlgorithem);
            IvParameterSpec ivparameterspec = new IvParameterSpec(key);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivparameterspec);
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] cipherText = decoder.decode(encryptedText.getBytes("UTF8"));
            decryptedText = new String(cipher.doFinal(cipherText), "UTF-8");

        } catch (Exception E) {
            System.err.println("decrypt Exception : "+E.getMessage());
        }
        return decryptedText;
    }
    

    // main 
    public static void main(String[] args) {
        
        String data = "";

        // Reading plaintext file
        try {
            File myObj = new File("plaintext.txt");
            Scanner myReader = new Scanner(myObj);
             while (myReader.hasNextLine()) {
                data = myReader.nextLine();
                System.out.println(data);
            }
            myReader.close();
         } catch (FileNotFoundException e) {
                System.out.println("An error occurred.");
                e.printStackTrace();
        }

        // Creating crypto.txt file
        try {
            File myObj = new File("crypto.txt");
            if (myObj.createNewFile()) {
                System.out.println("File created: " + myObj.getName());
            } else {
                System.out.println("File already exists.");
            }
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        // Creating cleartext.txt file
        try {
            File myObj = new File("cleartext.txt");
            if (myObj.createNewFile()) {
                 System.out.println("File created: " + myObj.getName());
             } else {
                 System.out.println("File already exists.");
             }
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        // using the ecrypt decrypt functions
        String encyptedString   = encrypt(data);
        String decryptString  = decrypt(encyptedString);
        
        System.out.println("Plain   String  : "+data);
        System.out.println("Encrypt String  : "+encyptedString);
        System.out.println("Decrypt String  : "+decryptString);

        // writing encrypted string in crypto.txt
        try {
            FileWriter myWriter = new FileWriter("crypto.txt");
            myWriter.write(encyptedString);
            myWriter.close();
            System.out.println("Crypto Text Written in Designated File");
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        //writng decrypted string in cleartext.txt
        try {
            FileWriter myWriter = new FileWriter("cleartext.txt");
            myWriter.write(decryptString);
            myWriter.close();
            System.out.println("Clear Text Written in Designated File");
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
        
        
    }   
}
