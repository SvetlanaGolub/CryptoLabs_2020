
public class GetResult {
    private final int first_index;
    private final int second_index;
    private final boolean same_thread;
    private final int thread;

    public GetResult(int first_index, int second_index, boolean same_thread, int thread) {
        this.first_index = first_index;
        this.second_index = second_index;
        this.same_thread = same_thread;
        this.thread = thread;
    }

    public int getFirst_index() {
        return first_index;
    }

    public int getSecond_index() {
        return second_index;
    }

    public boolean getSame_thread() {
        return same_thread;
    }

    public int getThread() {
        return thread;
    }

    public boolean equals(GetResult getResult) {
        return (getResult.first_index == first_index &&
                getResult.second_index == second_index &&
                getResult.same_thread == same_thread);
    }

    public void print() {
        System.out.println("First index: " + first_index);
        System.out.println("Second index: " + second_index);
        System.out.println("Same threads? " + same_thread);
    }

}
