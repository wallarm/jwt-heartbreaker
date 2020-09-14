package pingvin.tokenposition;

public class Dummy extends ITokenPosition {

    @Override
    public boolean positionFound() {
        return false;
    }

    @Override
    public String getToken() {
        return "e30=.e30=.";
    }

}
