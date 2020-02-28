import picocli.CommandLine;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.concurrent.Callable;


class filecrypt implements Callable<Integer>{
    @CommandLine.Option(names = {"-enc", "--encoder"}, description = "Chiffrement")
    boolean Encode;

    @CommandLine.Option(names = {"-dec", "--decoder"}, description = "Dechiffrement")
    boolean Decode;

    @CommandLine.Option(names = {"-key"}, description = "Key to crypt", required = true)
    String Key;

    @CommandLine.Option(names = {"-in", "--input"}, description = "Input file", required = true)
    File PathInputFile;

    @CommandLine.Option(names = {"-out", "--output"}, description = "Output file", required = true)
    File PathOutputFile;

    private static int fillSizeBytes(int size){
        int finalSize = size;
        while(finalSize%16 != 0){
            finalSize += finalSize%16;
        }
        return finalSize;
    }

    private static byte[] chiffrementAES(File fileToEncrypt, File fileEncrypted, SecretKey cle) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException {

        Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, cle,new IvParameterSpec(new byte[16]));
        FileInputStream inputStream = new FileInputStream(fileToEncrypt);
        byte[] inputBytes = new byte[fillSizeBytes((int)fileToEncrypt.length())];
        System.out.println("size Input:\t"+inputBytes.length);
        inputStream.read(inputBytes);

        byte[] outputBytes = c.doFinal(inputBytes);

        FileOutputStream outputStream = new FileOutputStream(fileEncrypted);
        outputStream.write(outputBytes);
        inputStream.close();
        outputStream.close();
        return outputBytes;
    }

    private static byte[] dechiffrementAES(File encryptedFile, File decryptedFile, SecretKey cle) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException {
        Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
        c.init(Cipher.DECRYPT_MODE, cle, new IvParameterSpec(new byte[16]));
        FileInputStream inputStream = new FileInputStream(encryptedFile);
        byte[] inputBytes = new byte[fillSizeBytes((int)encryptedFile.length())];
        System.out.println("size Input:\t"+inputBytes.length);
        inputStream.read(inputBytes);

        byte[] outputBytes = c.doFinal(inputBytes);

        FileOutputStream outputStream = new FileOutputStream(decryptedFile);
        outputStream.write(outputBytes);
        inputStream.close();
        outputStream.close();
        return  outputBytes;
    }

    public static SecretKey decodeKeyFromString(String keyStr) {
        /* Decodes a Base64 encoded String into a byte array */
        byte[] decodedKey = Base64.getDecoder().decode(keyStr);

        /* Constructs a secret key from the given byte array */
        SecretKey secretKey = new SecretKeySpec(decodedKey, 0,
                decodedKey.length, "AES");

        return secretKey;
    }

    public static void main(String[] args) {

       /* String[] chiffrement = {"-enc","-key","179bd8db7241569ad9a29d55e95be3cf","-in","File1.txt","-out","File2.txt"};
        new CommandLine(new filecrypt()).execute(chiffrement);
        System.out.println();*/
        String[] dechiffrement = {"-dec","-key","179bd8db7241569ad9a29d55e95be3cf","-in","File2.txt","-out","File3.txt"};
        new CommandLine(new filecrypt()).execute(dechiffrement);
    }

    @Override
    public Integer call() throws Exception {
        SecretKey originalKey = decodeKeyFromString(Key);

        //test de l'existence des fichiers
        if(!PathInputFile.exists()){
            System.out.println("Le fichiers input n'existe pas");
        }

        else if(!PathOutputFile.exists()){
            System.out.println("Le fichiers output n'existe pas");
        }

        //test taille de clé égale à 128bits en Hex
        else if(Key.length()!=32){
            System.out.println("Taille de la clé non valide");
        }

        //test de l'option enc/dec
        if(!Encode && !Decode){
            System.out.println("Veuilliez saisir un mode -enc/-dec");
        }

        if(Encode){
            System.out.println("encode");
            System.out.println("key\t"+ Key);
            System.out.println("input\t"+PathInputFile);
            System.out.println("output\t"+PathOutputFile);
            chiffrementAES(PathInputFile,PathOutputFile,originalKey);
        }

        if(Decode){
            System.out.println("decode");
            System.out.println("key\t"+ Key);
            System.out.println("input\t"+PathInputFile);
            System.out.println("output\t"+PathOutputFile);
            dechiffrementAES(PathInputFile,PathOutputFile,originalKey);
        }

        return null;
    }
}
