package burp;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Consumer;

public class TabClickHandler extends MouseAdapter {

    Consumer<MouseEvent> mouseEventConsumer;

    public TabClickHandler(Consumer<MouseEvent> consumer){
        this.mouseEventConsumer = consumer;
    }

    @Override
    public void mouseClicked(MouseEvent e) {
        this.mouseEventConsumer.accept(e);
    }
}
