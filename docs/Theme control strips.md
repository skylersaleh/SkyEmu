# Control strips should be in the top and left edges of the black outline 2 pixels away from the region button/image they are controlling and one pixel in width. 


## Red Component: (Resize Control)
#00xxxx stretch

#40xxxx tile

#80xxxx fixed

#C0xxxx reserved

#F0xxxx reserved


## Green Component: (Screen Control, ignored for non-bezels)

#xx00xx default

#xx40xx top screen cutout (places the top screen in this region)

#xx80xx bottom screen cutout (will be empty if not in DS mode)

#xxC0xx both screens (use if the theme doesn't want to control the layout of the DS screens)

#xxF0xx reserved


## Blue Component: (Gamepad Control, ignored for non-bezels, TBD will allow customization of default button placements)

#xxxx00 default

#xxxx40 reserved

#xxxx80 reserved

#xxxxC0 reserved

#xxxxF0 reserved
