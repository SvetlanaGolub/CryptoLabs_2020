package Json;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;


public class JsonReader {

    private static final String passwords_file_path = "D:\\MyDoc\\Desktop\\МИФЯГА\\crypt\\hkdf-SvetlanaGolub\\src\\Json\\passwords.json";
    private static final String weather_file_path = "D:\\MyDoc\\Desktop\\МИФЯГА\\crypt\\hkdf-SvetlanaGolub\\src\\Json\\weather.json";

    public static String whole_file_to_string() throws IOException {
        String file_to_string;
        File file = new File(weather_file_path);
        file_to_string = FileUtils.readFileToString(file, "UTF-8");
        return file_to_string;
    }


    public static List<String> get_values_from_json() throws IOException, ParseException {
        List<String> data_list = new ArrayList<>();
        Object obj = new JSONParser().parse(new FileReader(weather_file_path));
        JSONObject jo = (JSONObject) obj;
        JSONObject hourly_obj = (JSONObject) jo.get("hourly");
        JSONArray data_array = (JSONArray) hourly_obj.get("data");
        for (Object o : data_array) {
            JSONObject get_humidity = (JSONObject) o;
            Object humidity = get_humidity.get("precipIntensity");
            data_list.add(humidity.toString());
        }
        return data_list;
    }

    public static List<String> parsing_file() throws IOException, ParseException {
        Object obj = new JSONParser().parse(new FileReader(passwords_file_path));
        JSONObject jo = (JSONObject) obj;
        JSONArray passwords_array = (JSONArray) jo.get("passwords");
        List<String> passwords_list = new ArrayList<>();

        for (Object o : passwords_array) {
            passwords_list.add(o.toString());
        }
        return passwords_list;
    }
}
