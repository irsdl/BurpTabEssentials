# BurpTabEssentials
This changes the style of Burp Suite's Repeater tabs to help the testers. 

These features have been added by traversing the Java UI objects and manipulating them along the way. Therefore, it might not be as good as other built-in features, but that's the only thing we have at the moment to change the tab colours or their style :-)

# Installation and Usage
* Download the jar file from the [release](https://github.com/irsdl/BurpTabEssentials/releases) section
* Add it to Burp Suite using the Extender tab
* Right click on Repeater's tabs and see it yourself!

**Images**

![Darcula](https://github.com/irsdl/BurpTabEssentials/blob/master/images/darcula.png)

![Nimbus](https://github.com/irsdl/BurpTabEssentials/blob/master/images/nimbus.png)


**Limitations** 
* It **does not** save the settings – they need to be saved against the project file
* It's been tested against v2.0.x but should work fine against v1.7.x
* It might be confused if you add the extension more than once or reload it multiple times (try to restart burp)

Please feel free to report bugs or add features
