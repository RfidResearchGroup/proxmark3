The iceman fork.

NOTICE:

The official Proxmark repository is found here: https://github.com/Proxmark/proxmark3


NEWS:      

Whats in this fork?  I have scraped the web for different enhancements to the PM3 source code and not all of them ever found their way to the master branch. 
Among the stuff is

	* Jonor's hf 14a raw timing patch
	* Piwi's updates. (usually gets into the master)
	* Holiman's iclass, (usually gets into the master)
	* Marshmellow's LF fixes
	* Midnitesnake's Ultralight,  Ultralight-c enhancements
	* Izsh's lf peak modification / iir-filtering
	* Aspers's tips and tricks from inside the PM3-gui-tool, settings.xml and other stuff.
	* My own desfire, Ultralight extras, LF T55xx enhancements, bugs fixes (filelength, hf mf commands ), TNP3xxx lua scripts,  Awid26,  skidata scripts (will come)
	* other obscure patches like for the sammy-mode,  (offline you know), tagidentifications, defaultkeys. 
	
Give me a hint, and I'll see if I can't merge in the stuff you have. 

I don't actually know how to make small pull-request to github :( and that is the number one reason for me not pushing a lot of things back to the PM3 master.
	
PM3 GUI:

I do tend to rename and move stuff around, the official PM3-GUI from Gaucho will not work so well. *sorry*	

	  
DEVELOPMENT:

This fork is adjusted to compile on windows/mingw environment with Qt5.3.1 & GCC 4.8
For people with linux you will need to patch some source code and some small change to one makefile.  If you are lazy, you google the forum and find asper's or holimans makefile or you find your solution below.

Common errors linux/macOS finds
Error:
	* loclass/fileutils.c:15:2: warning: implicit declaration of function ‘_stat’ [-Wimplicit-function-declaration]
Solution:
	* Remove the "unscore" sign.   In linux you use without underscore, in windows you need a underscore. 
	
Error:  
	* \client\makefile  the parameter -lgdi32 
Solution:
	* Remove parameter.
	
Error:  
	* Using older Qt4.6 gives compilation errors.  
Solution
	* Upgrade to Qt5.3.1 
	OR 
	* Change these two line in  \client\makefile
		CXXFLAGS = -I$(QTDIR)/include -I$(QTDIR)/include/QtCore -I$(QTDIR)/include/QtGui -I$(QTDIR)/include/QtWidgets  -I/mingw/include
		QTLDLIBS = -L$(QTDIR)/lib  -lQt5Core -lQt5Gui -lQt5Widgets 
		
		TO
		
		CXXFLAGS = -I$(QTDIR)/include -I$(QTDIR)/include/QtCore -I$(QTDIR)/include/QtGui
		QTLDLIBS = -L$(QTDIR)/lib -lQtCore4 -lQtGui4
	

An old Qt4 version makefile is found here: http://www.icesql.se/proxmark3/code/linuxmakefile.txt  but this one doesn't have all new files in it. So I don't recommend it.

The Proxmark 3 is available for purchase (assembled and tested) from the
following locations:


January 2015, Sweden
iceman at host iuse.se