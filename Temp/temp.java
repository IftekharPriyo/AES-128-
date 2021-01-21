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




public class temp {
public static void main(String[] args) {
    File file = new File(args[0]);
    String data = "";
    System.out.println(file);

    try {
            // File myObj = new File(file);
            Scanner myReader = new Scanner(file);
             while (myReader.hasNextLine()) {
                data = myReader.nextLine();
                System.out.println(data);
            }
            myReader.close();
         } catch (FileNotFoundException e) {
                System.out.println("An error occurred.");
                e.printStackTrace();
        }
}
}