Works only with Anniversary Edition

Description

SKSE plugin that allows you to define what notifications will never show up in top left corner. You can remove notifications coming from the game itself (for example, critical/sneak strike) and from mods (Papyrus scripts that call Debug.Notification function).

You can configure everything in Data/SKSE/Plugins/NotificationFilter.ini file (look at screenshot for contents).

Check out powerofthree's Tweaks if you only want to remove critical/sneak strike notifications.

Requirements

SKSE - Anniversary Edition build
Microsoft Visual C++ 2022 Redistributable (x64)
Address Library for SKSE Plugins - All in one (Anniversary Edition)

Installation

Install with Mod Organizer 2/Vortex or put NotificationFilter.dll and NotificationFilter.ini manually in Data/SKSE/Plugins directory

How to use

Open Data/SKSE/Plugins/NotificationFilter.ini and add filters under [Filters] section
Add Hide=<Text> option to hide notifications with text <Text>
Add HideRegex=<Expression> option to hide notifications that match regular expression <Expression> (regular expressions use ECMAScript syntax)
INI file has more info how to configure this plugin (or look at screenshot)

Compatibility

Only works with Anniversary Edition, otherwise it just works™

Credits

Ryan ﻿for CommonLibSSE﻿
meh321﻿ for Address Library for SKSE Plugins﻿
