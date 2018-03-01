# Phabricator Installer
Interactive Bash script for installing and setting up a complete Phabricator installation on a modern Debian system (tested on Stretch).

![Screenshot](doc/screenshot1.png?raw=true)

## Disclaimer
Use the script at your own risk.

## Installation Requirements
At the moment this script is created and fine-tuned for Debian 9 only.

It has been designed for setting up a stand-alone server from scratch with all the bells and whistles that are needed for running a complete Phabricator installation.

You can start with a completely stripped down vanilla Debian installation that only runs SSH. The installer script will take care of installing missing dependencies automatically.

The script also makes the following assumptions that cannot be changed at the moment:

- You have a Debian server that is connected to a power outlet and the Internet
- You'd love to use NGINX as your web server of choice
- You're OK with installing PHP 7.1 from sury.org

If your current web server checks some or all of these boxes then you should be OK with running the installer on an already configured box.

If you're not happy with my exquisite choice of packages and services then you'll have to clean up the mess after the installation or install Phabricator by hand (see intro text above).

### Additional Goodies
- Installation of an update script and optional scheduling of automatic Phabricator updates. It will be located in the root of the Phabricator installation directory

## How to use?
Download the latest version to your Debian box. You can just copy & paste the following which should download and automatically run the installer:

```
wget https://raw.githubusercontent.com/tiguchi/phabricator-installer/master/phabricator-installer.sh && /bin/bash ./phabricator-installer.sh
```


## Your Contributions
I'm not sure how much time I can spare for continuous additions and maintenance work on this script. I created this script primarily for my own specific needs. But:

- Feel free to write bug and feature request tickets
	- Don't be mad if it takes me ages to respond.
	- Don't be mad if I don't respond at all :-(
	- Feel free to use tickets as your community support forum, so you can help each other out.
- Feel free to send me pull requests
	- Bug fixes and additional support for more distros welcome!

As a word of warning: I'm not a Bash wizard and I've been bashing (haha a pun) my head numerous times against the table because I had to deal with its countless charming little quirks and oddities. 

Especially if you're more experienced you may find cringeworthy things in my script. I try to give my best though.
