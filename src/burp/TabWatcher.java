package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ContainerEvent;
import java.awt.event.ContainerListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.List;
import java.util.function.Consumer;

public class TabWatcher implements ContainerListener {

    List<String> supportedTabTitles;
    Consumer<MouseEvent> mouseEventConsumer;

    public TabWatcher(List<String> supportedTabTitles, Consumer<MouseEvent> mouseEventConsumer){
        this.supportedTabTitles = supportedTabTitles;
        this.mouseEventConsumer = mouseEventConsumer;
    }

    public void addTabListener(JTabbedPane tabbedPane){
        tabbedPane.addContainerListener(this);
        for (Component component : tabbedPane.getComponents()) {
            addListenerToSupportedTabbedPanels(tabbedPane, component);
        }
    }

    public void removeTabListener(JTabbedPane tabbedPane){
        tabbedPane.removeContainerListener(this);
        for (Component component : tabbedPane.getComponents()) {
            removeListenerFromTabbedPanels(tabbedPane, component);
        }
    }

    @Override
    public void componentAdded(ContainerEvent e) {
        addListenerToSupportedTabbedPanels((JTabbedPane) e.getContainer(), e.getChild());
    }

    private void addListenerToSupportedTabbedPanels(JTabbedPane tabbedPane, Component tabComponent){
        //Check tab titles and continue for accepted tab paths.
        int componentIndex = tabbedPane.indexOfComponent(tabComponent);
        if(componentIndex == -1) {
            return;
        }
        String componentTitle = tabbedPane.getTitleAt(componentIndex);
        if(!supportedTabTitles.contains(componentTitle)) return;

        System.out.println("Adding listener to " + componentTitle);
        tabComponent.addMouseListener(new TabClickHandler(this.mouseEventConsumer));
    }

    @Override
    public void componentRemoved(ContainerEvent e) {
        removeListenerFromTabbedPanels((JTabbedPane) e.getContainer(), e.getChild());
    }

    private void removeListenerFromTabbedPanels(JTabbedPane tabbedPane, Component tabComponent){
        int componentIndex = tabbedPane.indexOfComponent(tabComponent);
        if(componentIndex == -1) {
            return;
        }
        String componentTitle = tabbedPane.getTitleAt(componentIndex);
        if(!supportedTabTitles.contains(componentTitle)) return;

        for (MouseListener mouseListener : tabComponent.getMouseListeners()) {
            if(mouseListener instanceof TabClickHandler){
                tabComponent.removeMouseListener(mouseListener);
            }
        }
    }
}
