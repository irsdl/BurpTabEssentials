package burp;

/*
 * Burp Tab Essentials
 * 
 * 
 * Developed by:
 *     Soroush Dalili (@irsdl)
 * 
 * Project link: https://github.com/irsdl/BurpTabEssentials
 * 
 * Released under AGPL v3.0 see LICENSE for more information
 * 
 * */

import java.awt.*;
import java.awt.event.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.*;

public class BurpExtender
		implements IBurpExtender, ITab, IExtensionStateListener {
	
	private String version = "0.1";
	private PrintWriter _stdout;
	private PrintWriter _stderr;
	private IBurpExtenderCallbacks _callbacks;
	private Boolean isActive = null;
	private Boolean isDebug = false;

	private JPanel dummyPanel;
	private TabWatcher tabWatcher;
	private JTabbedPane rootTabbedPane;

	public synchronized Boolean getIsActive() {
		if (this.isActive == null)
			setIsActive(false);
		return this.isActive;
	}

	public synchronized void setIsActive(Boolean isActive) {
		this.isActive = isActive;
	}

	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		_callbacks = callbacks;
		// obtain our output stream
		_stdout = new PrintWriter(_callbacks.getStdout(), true);
		_stderr = new PrintWriter(_callbacks.getStderr(), true);

		// set our extension name
		_callbacks.setExtensionName("Tab Essentials");
		callbacks.registerExtensionStateListener(this);

		// create our UI
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				dummyPanel = new JPanel(); //Will be removed shortly after it's added, doesn't need to be anything special!
				callbacks.addSuiteTab(BurpExtender.this);

				new Thread(() -> {
					boolean foundUI = false;
					int attemptsRemaining = 5;

					while (!foundUI && attemptsRemaining > 0) {
						try {
							getRootTabbedPane();
							foundUI = true;
						} catch (Exception e) {
							attemptsRemaining--;
							try {
								Thread.currentThread().sleep(1000);
							} catch (InterruptedException ignored) {}
						}
					}

					if(foundUI){
						tabWatcher = new TabWatcher(Arrays.asList("Repeater", "Intruder"), mouseEvent -> {
							tabClicked(mouseEvent);
						});

						if(BurpExtender.this.rootTabbedPane != null) {
							tabWatcher.addTabListener(BurpExtender.this.rootTabbedPane);
						}
						callbacks.removeSuiteTab(BurpExtender.this);
					}
				}).start();
			}
		});

	}

	@Override
	public String getTabCaption() {
		return "Tab Essentials";
	}

	@Override
	public Component getUiComponent() {
		return dummyPanel;
	}

	private void getRootTabbedPane(){
		if(this.dummyPanel != null) {
			JRootPane rootPane = ((JFrame) SwingUtilities.getWindowAncestor(this.dummyPanel)).getRootPane();
			rootTabbedPane = (JTabbedPane) rootPane.getContentPane().getComponent(0);
		}
	}

	private void tabClicked(final MouseEvent e){
		if(SwingUtilities.isRightMouseButton(e)){
			if(e.getComponent() instanceof JTabbedPane){
				JTabbedPane tabbedPane = (JTabbedPane) e.getComponent();
				int tabIndex = tabbedPane.getUI().tabForCoordinate(tabbedPane, e.getX(), e.getY());
				if(tabIndex < 0 || tabIndex > tabbedPane.getTabCount()-1) return;

				Component clickedTab = tabbedPane.getTabComponentAt(tabIndex);
				if(!(clickedTab instanceof Container)) return;

				String tabTitle = tabbedPane.getTitleAt(tabIndex);

				boolean isCTRL_Key = (e.getModifiers() & ActionEvent.CTRL_MASK) == ActionEvent.CTRL_MASK;
				boolean isALT_Key = (e.getModifiers() & ActionEvent.ALT_MASK) == ActionEvent.ALT_MASK;
				boolean isSHIFT_Key = (e.getModifiers() & ActionEvent.SHIFT_MASK) == ActionEvent.SHIFT_MASK;
				
				Component gotLabel = ((Container) clickedTab).getComponent(0);
				Font currentFont = gotLabel.getFont();
				Component gotExitBox = ((Container) clickedTab).getComponent(1); // removing the X button
				int maxSize = 40;
				int minSize = 10;
				int currentSize = currentFont.getSize();
				
				
				if(!isCTRL_Key && !isALT_Key && !isSHIFT_Key) {
					JPopupMenu popupMenu = createPopupMenu(tabbedPane, tabIndex, tabTitle, (Container) clickedTab);
					popupMenu.show(tabbedPane, e.getX(), e.getY());
				} else if (isCTRL_Key && !isALT_Key && !isSHIFT_Key) {
					// Make it bigger and bold when rightclick + ctrl
					if (currentSize < maxSize) {
						gotLabel.setFont(new Font(currentFont.getFontName(),
								Font.BOLD, ++currentSize));
						gotExitBox.setVisible(false);
					}
				} else if (isCTRL_Key && !isALT_Key && isSHIFT_Key) {
					// Make it smaller but bold when rightclick + ctrl + shift
					if (currentSize > minSize) {
						gotLabel.setFont(new Font(currentFont.getFontName(),
								Font.BOLD, --currentSize));
						gotExitBox.setVisible(false);
					}
				}else if (!isCTRL_Key && !isALT_Key && isSHIFT_Key) {
					// right click with shift: should make it green and big and bold
					Color textColor = new Color(0, 204, 51); // Green
					tabbedPane.setBackgroundAt(tabIndex, textColor);
					gotLabel.setFont(new Font("Dialog", Font.BOLD, 20));
					gotExitBox.setVisible(false);
				} else if (!isCTRL_Key && isALT_Key && !isSHIFT_Key) {
					// right click with alt: should make it blue and big and bold
					Color textColor = new Color(0, 102, 255); // BLUE
					tabbedPane.setBackgroundAt(tabIndex, textColor);
					gotLabel.setFont(new Font("Dialog", Font.BOLD, 20));
					gotExitBox.setVisible(false);
				} else if (isCTRL_Key && isALT_Key && !isSHIFT_Key) {
					// right click with alt and ctrl: should make it orange and big and bold
					Color textColor = new Color(255, 204, 51); // ORANGE
					tabbedPane.setBackgroundAt(tabIndex, textColor);
					gotLabel.setFont(new Font("Dialog", Font.BOLD, 20));
					gotExitBox.setVisible(false);
				}else if (isCTRL_Key && isALT_Key && isSHIFT_Key){
					// this is the funky mode! we don't serve drunks! but we do serve mad keyboard skillz!!
					// crazy mode

					tabbedPane.setBackgroundAt(tabIndex, Color.MAGENTA);
					gotLabel.setFont(new Font("Dialog", Font.BOLD, 20));
					gotExitBox.setVisible(false);
					Component selectedComp = tabbedPane.getSelectedComponent();
					selectedComp.setBackground(Color.GREEN); // change colour of surrounding
					tabbedPane.getParent().getParent().setBackground(Color.PINK);
					JTabbedPane parentJTabbedPane = (JTabbedPane) tabbedPane.getParent();

					for(int i=0; i <  parentJTabbedPane.getTabCount(); i++) {
						if (parentJTabbedPane.getTitleAt(i).equals("Repeater")){
							parentJTabbedPane.setTitleAt(i, "Repeater on ster0ids");
							break;
						}
					}
				}
			}
		}
	}

	private JPopupMenu createPopupMenu(JTabbedPane tabbedPane, int index, String title, Container tabComponent){
		Component labelComponent = tabComponent.getComponent(0);
		Component removeButton = tabComponent.getComponent(1);
		JPopupMenu popupMenu = new JPopupMenu();

		JMenuItem menuItem = new JMenuItem(title);
		menuItem.setEnabled(false);
		popupMenu.add(menuItem);
		popupMenu.addSeparator();

		JCheckBoxMenuItem closeButtonMenuItem = new JCheckBoxMenuItem("Remove Close Button");
		closeButtonMenuItem.addActionListener(e -> {
			removeButton.setVisible(!closeButtonMenuItem.isSelected());
		});
		closeButtonMenuItem.setSelected(!removeButton.isVisible());
		popupMenu.add(closeButtonMenuItem);

		JMenu fontSizeMenu = new JMenu("Font Size");
		float minFontSize = 10, maxFontSize = 40;
		for (float fontSize = minFontSize; fontSize < maxFontSize; fontSize+=2) {
			JCheckBoxMenuItem sizeItem = new JCheckBoxMenuItem(fontSize + "");
			float finalFontSize = fontSize;
			sizeItem.addActionListener(e -> {
				labelComponent.setFont(labelComponent.getFont().deriveFont(finalFontSize));
			});
			sizeItem.setSelected(labelComponent.getFont().getSize() == fontSize);
			fontSizeMenu.add(sizeItem);
		}
		popupMenu.add(fontSizeMenu);

		JCheckBoxMenuItem boldMenu = new JCheckBoxMenuItem("Bold");
		boldMenu.setSelected(labelComponent.getFont().isBold());
		boldMenu.addActionListener(e -> {
			Font font = labelComponent.getFont().deriveFont(labelComponent.getFont().getStyle() ^ Font.BOLD);
			labelComponent.setFont(font);
		});
		popupMenu.add(boldMenu);

		JCheckBoxMenuItem italicMenu = new JCheckBoxMenuItem("Italic");
		italicMenu.setSelected(labelComponent.getFont().isItalic());
		italicMenu.addActionListener(e -> {
			Font font = labelComponent.getFont().deriveFont(labelComponent.getFont().getStyle() ^ Font.ITALIC);
			labelComponent.setFont(font);
		});
		popupMenu.add(italicMenu);

		JMenuItem colorMenu = new JMenuItem("Set Foreground Color");
		colorMenu.addActionListener(e -> {
			Color color = JColorChooser.showDialog(colorMenu, "Select Foreground Color", labelComponent.getForeground());
			tabbedPane.setBackgroundAt(index, color);
		});
		popupMenu.add(colorMenu);

		return popupMenu;
	}

	@Override
	public void extensionUnloaded() {
		if(tabWatcher != null && rootTabbedPane != null){
			tabWatcher.removeTabListener(rootTabbedPane);
		}
	}

	// This is for later when I figure out how to save settings per project: https://twitter.com/irsdl/status/1138401437686423552
	private Object loadExtensionSettingHelper(String name, String type, Object defaultValue) {
		Object value = null;
		try {
			String temp_value = _callbacks.loadExtensionSetting(name);
			if (temp_value != null && !temp_value.equals("")) {
				switch (type.toLowerCase()) {
				case "int":
				case "integer":
					value = Integer.valueOf(temp_value);
					break;
				case "bool":
				case "boolean":
					value = Boolean.valueOf(temp_value);
					break;
				default:
					value = temp_value;
					break;
				}
			}
		} catch (Exception e) {
			_stderr.println(e.getMessage());
		}

		if (value == null) {
			value = defaultValue;
		}
		return value;
	}

}