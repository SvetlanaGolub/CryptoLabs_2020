import ForDiagrams.Get5Bits;
import Json.JsonReader;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class Main {

    private static final String context = "Svetlana";
    private static final int number_of_keys = 1000;
    private static final int size_of_salt = 256;

    private static final int size_of_keys = 64;
    private static final int size_of_hmac = 32;

    private static final int from_index = 0;
    private static final int number_of_bits = 5;
    private static final int from_index_for_weather = 0;


    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ParseException {
        byte[] salt = new byte[size_of_salt];
        SecureRandom.getInstanceStrong().nextBytes(salt);
        byte[] ctx = context.getBytes(StandardCharsets.UTF_8);
//Вычисляем первые 5 бит поминутных измерений для диаграммы
        List<String> all_values = JsonReader.get_values_from_json();
        System.out.println("\n" + all_values);
        List<byte[]> values_to_byte = new ArrayList<>();
        for (String value : all_values) {
            values_to_byte.add(value.getBytes(StandardCharsets.UTF_8));
        }
        for (byte[] value : values_to_byte) {
            System.out.print(Get5Bits.get_bits(value, from_index_for_weather, number_of_bits) + " ");
        }
        System.out.println();

//Получаем 1000 ключей с помощью HKDF
        byte[] data = JsonReader.whole_file_to_string().getBytes(StandardCharsets.UTF_8);
        List<byte[]> hkdf_keys = HKDF.get_hkdf_keys(salt, data, ctx, number_of_keys);

        for (byte[] hkdf_key : hkdf_keys) {
            System.out.print(Get5Bits.get_bits(hkdf_key, from_index, number_of_bits) + " ");
        }

//Вынимаем пароли из файла
        List<String> all_passwords = JsonReader.parsing_file();
        System.out.println("\n" + all_passwords);
//Вычисляем первые 5 бит каждого пароля для построения диаграммы
        List<byte[]> pass_to_byte = new ArrayList<>();
        for (String password : all_passwords) {
            pass_to_byte.add(password.getBytes(StandardCharsets.UTF_8));
        }
        for (byte[] pass : pass_to_byte) {
            System.out.print(Get5Bits.get_bits(pass, from_index, number_of_bits) + " ");
        }
//Получаем ключ для каждого пароля с помощью pbkdf2
        System.out.println();
        List<byte[]> all_pbkdf2_keys = new ArrayList<>();
        int number_of_blocks = size_of_keys / size_of_hmac;
        for (String password : all_passwords) {
            byte[] password_to_byte = password.getBytes(StandardCharsets.UTF_8);
            byte[] pbkdf2_key = PBKDF2.pbkdf(salt, password_to_byte, number_of_blocks);
            all_pbkdf2_keys.add(pbkdf2_key);
        }
//Выбираем первые 5 бит для построения диаграммы
        for (byte[] pbkdf_key : all_pbkdf2_keys) {
            System.out.print(Get5Bits.get_bits(pbkdf_key, from_index, number_of_bits) + " ");
        }
    }
}
