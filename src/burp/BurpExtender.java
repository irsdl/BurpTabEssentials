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

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

public class BurpExtender
		implements IBurpExtender, ITab, IMessageEditorTabFactory, IMessageEditorTab, ComponentListener {
	
	private String version = "0.1";
	private PrintWriter _stdout;
	private PrintWriter _stderr;
	private IBurpExtenderCallbacks _callbacks;
	private Boolean isActive = null;
	private Boolean isDebug = false;

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

		// create our UI
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {

				_callbacks.registerMessageEditorTabFactory(BurpExtender.this);

			}
		});

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

	@Override
	public String getTabCaption() {
		// TODO Auto-generated method stub
		return "Tab Essentials";
	}

	@Override
	public Component getUiComponent() {
		JPanel jPanel = new JPanel();
		jPanel.addComponentListener(this);
		return jPanel;
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		// TODO Auto-generated method stub
		return this;
	}

	@Override
	public boolean isEnabled(byte[] content, boolean isRequest) {
		if (getIsActive()) {
			return false;
		} else {
			return true;
		}

	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		// TODO Auto-generated method stub

	}

	@Override
	public byte[] getMessage() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isModified() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public byte[] getSelectedData() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void componentHidden(ComponentEvent e) {
		// We use this to detect a load. Ideally, we need to run this only once
		if(isDebug) _stdout.println("componentHidden");
		
		if (!getIsActive()) {

			try {
				Component parentComponent = e.getComponent().getParent().getParent().getParent().getParent().getParent()
						.getParent();
				if (parentComponent instanceof JTabbedPane) {
					// we call it repeater but it might be a different menu such as "Extension"!
					JTabbedPane repeater_tabbed_pane = (JTabbedPane) parentComponent;
					int tab_pos = repeater_tabbed_pane.getSelectedIndex();
					if(isDebug) _stdout.println(repeater_tabbed_pane.getTitleAt(tab_pos));
					Container tabComp = (Container) repeater_tabbed_pane.getTabComponentAt(tab_pos);
					Component[] tabComComps = tabComp.getComponents();
					if (tabComComps.length == 2) {
						repeater_tabbed_pane.addMouseListener(new MouseAdapter() {
							@Override
							public void mousePressed(MouseEvent e) {
								boolean isCTRL_Key = false;
								boolean isALT_Key = false;
								boolean isSHIFT_Key = false;
								
								if (SwingUtilities.isRightMouseButton(e)) {
									if ((e.getModifiers() & ActionEvent.CTRL_MASK) == ActionEvent.CTRL_MASK) {
										isCTRL_Key = true;
									}
									
									if ((e.getModifiers() & ActionEvent.ALT_MASK) == ActionEvent.ALT_MASK) {
										isALT_Key = true;
									}
									
									if ((e.getModifiers() & ActionEvent.SHIFT_MASK) == ActionEvent.SHIFT_MASK) {
										isSHIFT_Key = true;
									}
									
									Component parentComponent = e.getComponent();
									if (parentComponent instanceof JTabbedPane) {
										JTabbedPane repeater_tabbed_pane = (JTabbedPane) parentComponent;

										int tab_pos = repeater_tabbed_pane.getUI()
												.tabForCoordinate(repeater_tabbed_pane, e.getX(), e.getY());
										if (tab_pos > -1 && tab_pos < repeater_tabbed_pane.getTabCount() - 1) {
											Container tabComp = (Container) repeater_tabbed_pane
													.getTabComponentAt(tab_pos);
											Component[] tabComComps = tabComp.getComponents();
											if (tabComComps.length == 2) {
												// We don't want change other menus! Can we? Yes we can!
												Component gotLabel = tabComComps[0];
												Font currentFont = gotLabel.getFont();
												

												Component gotExitBox = tabComComps[1]; // removing the X button

												// Making the text bigger
												int maxSize = 40;
												int minSize = 10;
												int currentSize = currentFont.getSize();
												if(isDebug) _stdout.println("currentSize: " + currentSize);

												if (isCTRL_Key && !isALT_Key && !isSHIFT_Key) {
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
												} else if(!isCTRL_Key && !isALT_Key && !isSHIFT_Key) {
													// just right click
													// right click should make it big and bold or reset the style
													Color textColor = new Color(255, 0, 51); // RED
													
													if (gotExitBox.isVisible()) {
														// We want to change the colour or make it bold!
														repeater_tabbed_pane.setBackgroundAt(tab_pos, textColor); 
														gotLabel.setFont(new Font("Dialog", Font.BOLD, 20)); 
														gotExitBox.setVisible(false);
													} else {
														// remove the colour and style
														repeater_tabbed_pane.setBackgroundAt(tab_pos, null); 
														gotLabel.setFont(null);
														gotExitBox.setVisible(true);
													}
												}else if (!isCTRL_Key && !isALT_Key && isSHIFT_Key) {
													// right click with shift: should make it green and big and bold
													Color textColor = new Color(0, 204, 51); // Green
													repeater_tabbed_pane.setBackgroundAt(tab_pos, textColor); 
													gotLabel.setFont(new Font("Dialog", Font.BOLD, 20)); 
													gotExitBox.setVisible(false);
												} else if (!isCTRL_Key && isALT_Key && !isSHIFT_Key) {
													// right click with alt: should make it blue and big and bold 
													Color textColor = new Color(0, 102, 255); // BLUE
													repeater_tabbed_pane.setBackgroundAt(tab_pos, textColor); 
													gotLabel.setFont(new Font("Dialog", Font.BOLD, 20)); 
													gotExitBox.setVisible(false);
												} else if (isCTRL_Key && isALT_Key && !isSHIFT_Key) {
													// right click with alt and ctrl: should make it orange and big and bold
													Color textColor = new Color(255, 204, 51); // ORANGE
													repeater_tabbed_pane.setBackgroundAt(tab_pos, textColor); 
													gotLabel.setFont(new Font("Dialog", Font.BOLD, 20)); 
													gotExitBox.setVisible(false);
												}else if (isCTRL_Key && isALT_Key && isSHIFT_Key){
													// this is the funky mode! we don't serve drunks! but we do serve mad keyboard skillz!!
													// crazy mode
													
													repeater_tabbed_pane.setBackgroundAt(tab_pos, Color.MAGENTA); 
													gotLabel.setFont(new Font("Dialog", Font.BOLD, 20)); 
													gotExitBox.setVisible(false);
													Component selectedComp = repeater_tabbed_pane.getSelectedComponent();
													selectedComp.setBackground(Color.GREEN); // change colour of surrounding
													repeater_tabbed_pane.getParent().getParent().setBackground(Color.PINK);
													JTabbedPane parentJTabbedPane = (JTabbedPane) repeater_tabbed_pane.getParent();
													
													for(int i=0; i <  parentJTabbedPane.getTabCount(); i++) {
														if (parentJTabbedPane.getTitleAt(i).equals("Repeater")){
															parentJTabbedPane.setTitleAt(i, "Repeater on ster0id");
															break;
														}
													}
												}										
											}
										}
									}
								}
							}
						});

						setIsActive(true);
					}
				}
			} catch (Exception err) {
				_stderr.println(err.getMessage());
			}

		}
	}

	@Override
	public void componentMoved(ComponentEvent e) {
		// We don't use this - no need to hack this!
		if(isDebug) _stdout.println("componentMoved");
	}

	@Override
	public void componentResized(ComponentEvent e) {
		// We don't use this - no need to hack this!
		if(isDebug) _stdout.println("componentResized");
	}

	@Override
	public void componentShown(ComponentEvent e) {
		// We don't use this - no need to hack this!
		if(isDebug) _stdout.println("componentShown");
	}

}