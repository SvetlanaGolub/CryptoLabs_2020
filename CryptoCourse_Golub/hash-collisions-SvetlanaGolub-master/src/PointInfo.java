import java.util.Arrays;

public class PointInfo {
    private final int iter;
    private final byte[] hash;
    private final int thread;

    public PointInfo(int iter, byte[] hash, int thread){
        this.iter = iter;
        this.hash = hash;
        this.thread = thread;
    }

    public int getIter(){
        return iter;
    }

    public byte[] getHash(){
        return hash;
    }

    public int getThread(){
        return thread;
    }

    public boolean equals(byte[] hash) {
        return Arrays.equals(this.hash, hash);
    }

    public void print(){
        System.out.println("Thread: " + thread);
        System.out.println("Iter: " + iter);
        System.out.println("Hash: " + Arrays.toString(hash));
    }
}
