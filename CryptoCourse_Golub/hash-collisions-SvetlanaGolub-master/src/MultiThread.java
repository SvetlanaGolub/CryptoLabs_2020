import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class MultiThread {

    private long minus_time;
    private int list_size;

    public MultiThread(long minus_time, int list_size) {
        this.minus_time = minus_time;
        this.list_size = list_size;
    }

    public MultiThread(){}

    public void get_collision(byte[] first_start, byte[] second_start, int count_collision) throws NoSuchAlgorithmException, IOException {
        long start_time = System.currentTimeMillis();
        byte[] current;
        byte[] another;
        //в GetResult хранятся два индекса одинаковых хэшей, в разных или одинаковых потоках найдены, список отл точек
        GetResult get_indexes = get_indexes(first_start, second_start);
        //get_indexes.print();
        if (get_indexes.getThread() == 0) {
            current = first_start;
            another = second_start;
        } else {
            current = second_start;
            another = first_start;
        }
        Pollard.compare(get_indexes, current, another, count_collision);
        minus_time = System.currentTimeMillis() - start_time - minus_time;
    }

    public GetResult get_indexes(byte[] first_start, byte[] second_start) throws NoSuchAlgorithmException {
        List<PointInfo> point_list = new ArrayList<>();
        int first_iter = 0;
        int second_iter = 0;
        Pollard first_thread = new Pollard(0, first_iter);
        Pollard second_thread = new Pollard(1, second_iter);
        PointInfo first_point = new PointInfo(0, first_start, 0);
        PointInfo second_point = new PointInfo(0, second_start, 1);
        while (true) {//находим отличительные точки
            first_point = first_thread.get_point(first_point.getHash(), System.currentTimeMillis());
            second_point = second_thread.get_point(second_point.getHash(), System.currentTimeMillis());
            for (PointInfo p : point_list) {
                if (p.equals(first_point.getHash())) {
                    boolean same_thread = (first_point.getThread() == p.getThread());
                    list_size = point_list.size();
                    point_list.clear();
                    minus_time = Math.min(first_thread.getCurrent_time(), second_thread.getCurrent_time());//выбираем поток, потративший меньше времени
                    return new GetResult(first_point.getIter(), p.getIter(), same_thread, first_point.getThread());
                    //в GetResult хранятся индексы одинаковых хэшей, в одном ли потоке найдены и поток, который нашёл
                }
                if (p.equals(second_point.getHash())) {
                    boolean same_thread = (second_point.getThread() == p.getThread());
                    list_size = point_list.size();
                    point_list.clear();
                    minus_time = Math.min(first_thread.getCurrent_time(), second_thread.getCurrent_time());
                    return new GetResult(second_point.getIter(), p.getIter(), same_thread, second_point.getThread());
                }
            }
            point_list.add(first_point);
            point_list.add(second_point);
        }


    }

    public int getList_size() {
        return list_size;
    }

    public long getMinus_time() {
        return minus_time;
    }

}
