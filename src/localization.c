#include "IconsForkAwesome.h"
#include "stdlib.h"
#include "localization.h"
#include <string.h>
#include <stdio.h>

//#define SHOW_TRANSLATE_ME 1

//Special thanks to https://github.com/shooterspps for the Chinese Translation
static char* zh_localization_array[]={
    ICON_FK_FILE_O " Load Game", ICON_FK_FILE_O " 载入游戏",
    "Up", "上",
    "Down", "下",
    "Left", "左",
    "Right", "右",
    "Start", "开始",
    "Select", "选择",
    "Fold Screen (NDS)", "折叠屏幕 (NDS)",
    "Tap Screen (NDS)", "点击屏幕 (NDS)",
    "Emulator " ICON_FK_PAUSE "/" ICON_FK_PLAY, "模拟器 " ICON_FK_PAUSE "/" ICON_FK_PLAY, 
    "Emulator " ICON_FK_BACKWARD,        "模拟器 " ICON_FK_BACKWARD,
    "Emulator " ICON_FK_FORWARD,         "模拟器 " ICON_FK_FORWARD,
    "Emulator " ICON_FK_FAST_FORWARD,    "模拟器 " ICON_FK_FAST_FORWARD,
    "Capture State 0", "即时存档 0",
    "Restore State 0", "即时读档 0",
    "Capture State 1", "即时存档 1",
    "Restore State 1", "即时读档 1",
    "Capture State 2", "即时存档 2",
    "Restore State 2", "即时读档 2",
    "Capture State 3", "即时存档 3",
    "Restore State 3", "即时读档 3",
    "Analog Up/Down", "摇杆 上/下",
    "Analog Left/Right", "摇杆 左/右",
    "Analog L", "扳机 L",
    "Analog R", "扳机 R",
    "Display FPS: %2.1f\n", "显示屏 FPS: %2.1f\n",
    "Emulation FPS: %2.1f\n", "模拟器 FPS: %2.1f\n",
    ICON_FK_VOLUME_UP " Audio", ICON_FK_VOLUME_UP " 音频",
    "Left Audio Channel", "音频左声道",
    "Right Audio Channel", "音频右声道",
    "Channel 0", "声道 0",
    "Channel 1", "声道 1",
    "Channel 2", "声道 2",
    "Channel 3", "声道 3",
    "Channel 4", "声道 4",
    "Channel 5", "声道 5",
    "Channel 6", "声道 6",
    "Channel 7", "声道 7",
    "Channel 8", "声道 8",
    "Channel 9", "声道 9",
    "Channel A", "声道 A",
    "Channel B", "声道 B",
    "Channel C", "声道 C",
    "Channel D", "声道 D",
    "Channel E", "声道 E",
    "Channel F", "声道 F",
    "Channel 1 (Square)", "声道 1 (方形)",
    "Channel 2 (Square)", "声道 2 (方形)",
    "Channel 3 (Wave)", "声道 3 (波形)",
    "Channel 4 (Noise)", "声道 4 (噪声)",
    "Channel A (FIFO)", "声道 A (FIFO)",
    "Channel B (FIFO)", "声道 B (FIFO)",
    "Audio Ring (Samples Available: %d)", "音频环绕 (可用采样: %d)",
    "Audio Watchdog Triggered %d Times", "音频定时触发 %d 时间",
    ICON_FK_INFO_CIRCLE " Build Info", ICON_FK_INFO_CIRCLE " 构建信息",
    "Commit Hash:", "哈希值提交:",
    ICON_FK_SERVER " Registers", ICON_FK_SERVER " 寄存器",
    ICON_FK_LIST_OL " Disassembly", ICON_FK_LIST_OL " 反汇编",
    ICON_FK_EXCHANGE " Read/Write Memory Address", ICON_FK_EXCHANGE " 读/写内存地址",
    "address", "地址",
    "data (32 bit)", "数据 (32 bit)",
    "data (16 bit)", "数据 (16 bit)",
    "data (8 bit)", "数据 (8 bit)",
    "data (signed 32b)", "数据 (写入 32b)",
    "data (signed 16b)", "数据 (写入 16b)",
    "data (signed 8b)", "数据 (写入 8b)",
    ICON_FK_PENCIL_SQUARE_O " Memory", ICON_FK_PENCIL_SQUARE_O " 内存",
    ICON_FK_AREA_CHART " Emulator Stats", ICON_FK_AREA_CHART " 模拟器统计",
    "Show/Hide %s Panel\n", "显示/隐藏 %s面板\n",
    "Press new button " ICON_FK_SIGN_IN, "按下按键 " ICON_FK_SIGN_IN,
    "Move Axis ", "移动轴 ",
    "Not bound", "不绑定",
    "Hat %d %s", "方向 %d %s",
    "Analog %d %s", "手柄轴 %d %s",
    "Key %d", "按键 %d",
    "Analog %d (%0.2f)", "手柄轴 %d (%0.2f)",
    "Load ROM from file (.gb, .gbc, .gba, .zip)", "从文件中载入 ROM (.gb, .gbc, .gba, .zip)",
    "You can also drag & drop a ROM to load it", "你也可以通过拖放载入一个 ROM",
    "Load ROM(.gb, .gbc, .gba, .zip), save(.sav), or GBA bios (gba_bios.bin) from file", "从文件中载入 ROM(.gb, .gbc, .gba, .zip), save(.sav), 或 GBA bios (gba_bios.bin)",
    "You can also drag & drop a ROM/save file to load it", "你也可以通过拖放载入一个 ROM/存档文件",
    "Open ROM", "打开 ROM",
    ICON_FK_CLOCK_O " Load Recently Played Game", ICON_FK_CLOCK_O " 载入最近玩过的游戏",
    ICON_FK_DOWNLOAD " Export Save", ICON_FK_DOWNLOAD  " 导出存档",
    "No recently played games", "最近没有玩过游戏",
    ICON_FK_GAMEPAD " Controllers", ICON_FK_GAMEPAD " 控制器",
    "Controller", "控制器",
    "No Controller", "无控制器",
    "Reset Default Controller Bindings", "重置控制器默认绑定",
    "Rumble Supported", "支持震动",
    "Rumble Not Supported", "不支持震动",
    ICON_FK_FLOPPY_O " Save States", ICON_FK_FLOPPY_O " 即时存档",
    "Save Slot %d", "存档位置 %d",
    "Capture", "存档",
    "Restore", "读档",
    "This save state came from an incompatible build. SkyEmu has attempted to recover it, but there may be issues", "这个即时存档来自一个不兼容的构建. SkyEmu 已经尝试恢复, 但可能会有问题",
    ICON_FK_DESKTOP " Display Settings", ICON_FK_DESKTOP " 显示设置",
    "Screen Shader", "屏幕着色器",
    "Pixelate\0Bilinear\0LCD\0LCD & Subpixels\0Smooth Upscale (xBRZ)\0", "像素化\0双线性\0LCD\0LCD & 子像素\0高级平滑过滤 (xBRZ)\0",
    "Screen Rotation", "屏幕旋转",
    "0 degrees\00090 degrees\000180 degrees\000270 degrees\0", "0°\00090°\000180°\000270°\0",
    "Color Correction", "颜色校正",
    "Strength: %.2f", "强度: %.2f",
    "Screen Ghosting", "屏幕残影",
    "Force Integer Scaling", "强制整数缩放",
    "Stretch Screen to Fit", "拉伸适应屏幕",
    "Game Boy Color Palette", "Game Boy Color 调色板",
    "GB Palette %d", "GB 调色板 %d",
    "Reset Palette to Defaults", "重置调色板默认值",
    ICON_FK_KEYBOARD_O " Keybinds", ICON_FK_KEYBOARD_O " 键盘快捷键",
    "Reset Default Keybinds", "重置键盘快捷键默认值",
    ICON_FK_WRENCH " Advanced",ICON_FK_WRENCH " 高级",
    "Light Mode", "浅色模式",
    "Show Debug Tools", "显示调试工具",
    "Adjust volume", "调节音量",
    "Show/Hide Menu Panel", "显示/隐藏菜单面板",
    "Rewind at 8x speed", "以8倍速度倒带",
    "Rewind at 4x speed", "以4倍速度倒带",
    "Toggle pause/play.\n When paused, the rom selection screen will be shown.", "切换暂停/游玩.\n 暂停时, 屏幕显示选择 rom 菜单.",
    "Run at 2x Speed", "以2倍速度快进",
    "Run at the fastest speed possible", "速度无限制快进",
    "Screen", "屏幕",
    "LCD Shader Init", "LCD 着色器初始化",
    "Menu", "菜单",
    "Copy as..", "复制..",
    "Current", "当前",
    "Original", "原始",
    "Opacity", "不透明度",
    ICON_FK_HAND_O_RIGHT " Touch Control Settings", ICON_FK_HAND_O_RIGHT " 触摸控制设置",
    "Hide when inactive", "不活动时隐藏",
    ICON_FK_FILE_O " Dump Memory to File", ICON_FK_FILE_O " 转储内存文件",
    "Start Address", "起始地址",
    "Size", "大小",
    "Save Memory Dump", "保存转储内存",
    ICON_FK_RANDOM " Last Branch Locations", ICON_FK_RANDOM " 最后分支位置",
    "Opacity: %.2f", "不透明度: %.2f",
    "Step Instruction", "步进指令",
    "Disconnect Log", "断开日志",
    ICON_FK_FOLDER_OPEN " Open File From Disk", ICON_FK_FOLDER_OPEN " 从磁盘打开文件",
    "Exit File Browser", "退出文件浏览",
    "Go back to recently loaded games", "返回最近载入的游戏",
    "Go to parent directory", "转到上级目录",
    "UP", "上",
    "DOWN", "下",
    "LEFT", "左",
    "RIGHT", "右",
    "Reset Game", "重置游戏",
    "Turbo A", "连发 A",
    "Turbo B", "连发 B",
    "Turbo X", "连发 X",
    "Turbo Y", "连发 Y",
    "Turbo L", "连发 L",
    "Turbo R", "连发 R",
    "Solar Sensor+", "太阳能传感器+",
    "Solar Sensor-", "太阳能传感器-",
    "Theme", "主题",
    "Solar Sensor", "太阳能传感器",
    "Brightness: %.2f", "亮度: %.2f",
    "Dark\0Light\0Black\0", "深色\0浅色\0黑色\0",
    "Always Show Menu/Nav Bar", "始终显示菜单/导航栏",
    "Language", "语言",

    "SPACE", "空格",
    "ESCAPE", "ESC",
    "ENTER", "回车",
    "BACKSPACE", "退格键",
    "INSERT", "插入",
    "DELETE", "删除",
    "RIGHT", "右",
    "LEFT", "左",
    "DOWN", "下",
    "UP", "上",
    "LEFT_SHIFT", "左 Shift",
    "LEFT_CONTROL", "左 Control",
    "LEFT_ALT", "左 Alt",
    "LEFT_SUPER", "左 Super",
    "RIGHT_SHIFT", "右 Shift",
    "RIGHT_CONTROL", "右 Control",
    "RIGHT_ALT", "右 Alt",
    "RIGHT_SUPER", "右 Super",
    "MENU", "菜单",
    "Enable Turbo and Hold Button Modifiers", "启用按住按键连发",
    "Scale", "缩放",
    "Scale: %.2f","缩放 %.2f",
    "GBA Color Correction Type","GBA 颜色校正类型",
    ICON_FK_TEXT_HEIGHT " GUI",ICON_FK_TEXT_HEIGHT " 界面",
    "Full Screen","全屏",
    ICON_FK_CODE_FORK " Additional Search Paths",ICON_FK_CODE_FORK " 额外搜索路径",
    "Save File/State Path","即时存档/文件路径",
    "BIOS/Firmware Path","BIOS/固件路径",
    "Create new save files in Save Path","在存档路径中创建新的存档文件",
    ICON_FK_CROSSHAIRS " Located BIOS/Firmware Files",ICON_FK_CROSSHAIRS " BIOS/固件文件位置",
    "Force GB games to run in DMG mode","强制在 DMG 模式下运行 GB 游戏",
    "Enable HTTP Control Server","启用 HTTP 服务器控制",
    "Server Port","服务器端口",
    "Toggle Full Screen","切换全屏",
    NULL,NULL
};


// Armenian translation by https://github.com/udxs
static char* hy_localization_array[]={
    ICON_FK_FILE_O " Load Game", ICON_FK_FILE_O " Տեղադրեք Խաղ",
    "Up", "Վերև",
    "Down", "Ներքև",
    "Left", "Ձախ",
    "Right", "Աջ",
    "Start", "Սկսեք",
    "Select", "Ընտրեք",
    "Fold Screen (NDS)", "Ծալեք (NDS)",
    "Tap Screen (NDS)", "Հպեք (NDS)",
    "Emulator " ICON_FK_PAUSE "/" ICON_FK_PLAY, "Վերարտադ. " ICON_FK_PAUSE "/" ICON_FK_PLAY, 
    "Emulator " ICON_FK_BACKWARD,        "Վերարտադ. " ICON_FK_BACKWARD,
    "Emulator " ICON_FK_FORWARD,         "Վերարտադ. " ICON_FK_FORWARD,
    "Emulator " ICON_FK_FAST_FORWARD,    "Վերարտադ. " ICON_FK_FAST_FORWARD,
    "Capture State 0", "Նկարեք Վիճակը 0",
    "Restore State 0", "Վերա. Վիճակը 0",
    "Capture State 1", "Նկարեք Վիճակը 1",
    "Restore State 1", "Վերա. Վիճակը 1",
    "Capture State 2", "Նկարեք Վիճակը 2",
    "Restore State 2", "Վերա. Վիճակը 2",
    "Capture State 3", "Նկարեք Վիճակը 3",
    "Restore State 3", "Վերա, Վիճակը 3",
    "Analog Up/Down", "Անալոգային Վերև/Ներքև",
    "Analog Left/Right", "Անալոգային Ձախ/Աջ",
    "Analog L", "Անալոգային L",
    "Analog R", "Անալոգային R",
    "Display FPS: %2.1f\n", "Էկրանի Թարմացումն Վայրկյանում: %2.1f\n",
    "Emulation FPS: %2.1f\n", "Հաշվողական Թարմացում Վայրկյանում: %2.1f\n",
    ICON_FK_VOLUME_UP " Audio", ICON_FK_VOLUME_UP " Ձայն",
    "Left Audio Channel", "Ձախ Ձայնային Ալիք",
    "Right Audio Channel", "Աջ Ձայնային Ալիք",
    "Channel 0", "Ալիք 0",
    "Channel 1", "Ալիք 1",
    "Channel 2", "Ալիք 2",
    "Channel 3", "Ալիք 3",
    "Channel 4", "Ալիք 4",
    "Channel 5", "Ալիք 5",
    "Channel 6", "Ալիք 6",
    "Channel 7", "Ալիք 7",
    "Channel 8", "Ալիք 8",
    "Channel 9", "Ալիք 9",
    "Channel A", "Ալիք A",
    "Channel B", "Ալիք B",
    "Channel C", "Ալիք C",
    "Channel D", "Ալիք D",
    "Channel E", "Ալիք E",
    "Channel F", "Ալիք F",
    "Channel 1 (Square)", "Ալիք 1 (Քառակուսի)",
    "Channel 2 (Square)", "Ալիք 2 (Քառակուսի)",
    "Channel 3 (Wave)", "Ալիք 3 (Ալիք)",
    "Channel 4 (Noise)", "Ալիք 4 (Աղմուկ)",
    "Channel A (FIFO)", "Ալիք A (FIFO)",
    "Channel B (FIFO)", "Ալիք B (FIFO)",
    "Audio Ring (Samples Available: %d)", "Ձայնային Օղակ (Մնացած Վանկերը: %d)",
    "Audio Watchdog Triggered %d Times", "Ձայնային Ժամապահը Գործարկվել է %d Անգամ",
    ICON_FK_INFO_CIRCLE " Build Info", ICON_FK_INFO_CIRCLE " Կառուցման Տեղեկատվություն",
    "Commit Hash:", "«Git» Վերսիա տարբերակը:",
    ICON_FK_SERVER " Registers", ICON_FK_SERVER " Ռեգիստրներ",
    ICON_FK_LIST_OL " Disassembly", ICON_FK_LIST_OL " Ապակառուցում",
    ICON_FK_EXCHANGE " Read/Write Memory Address", ICON_FK_EXCHANGE " Կարդեք/Գրեք Հիշողության Հասցեները",
    "address", "հասցեն",
    "data (32 bit)", "տվյալներ (32 բիթ)",
    "data (16 bit)", "տվյալներ (16 բիթ)",
    "data (8 bit)", "տվյալներ (8 բիթ)",
    "data (signed 32b)", "տվյալներ (բացասականելի 32բ)",
    "data (signed 16b)", "տվյալներ (բացասականելի 16բ)",
    "data (signed 8b)", "տվյալներ (բացասականելի 8բ)",
    ICON_FK_PENCIL_SQUARE_O " Memory", ICON_FK_PENCIL_SQUARE_O " Հիշողություն",
    ICON_FK_AREA_CHART " Emulator Stats", ICON_FK_AREA_CHART " Սիմուլյատորի Վիճակագրություն",
    "Show/Hide %s Panel\n", "Ցույց տվեք/թաքցնվեք %s վահանակը\n",
    "Press new button " ICON_FK_SIGN_IN, " Սեղմեք նոր կոճակ" ICON_FK_SIGN_IN,
    "Move Axis ", "Տեղափոխեք Առանցքը",
    "Not bound", "Անկապված",
    "Hat %d %s", "Ուղղորդող %d %s",
    "Analog %d %s", "Անալոգ %d %s",
    "Key %d", "Կոճակ %d",
    "Analog %d (%0.2f)", "Անալոգ %d (%0.2f)",
    "Load ROM from file (.gb, .gbc, .gba, .zip)", "Տեղադրեք ROM-ը (.gb, .gbc, .gba, .zip)",
    "You can also drag & drop a ROM to load it", "Կարող եք նաև քաշել և թողնել որևէ ROM՝ այն տեղադրելու համար",
    "Load ROM(.gb, .gbc, .gba, .zip), save(.sav), or GBA bios (gba_bios.bin) from file", "Տեղադրելու ROM (.gb, .gbc, .gba, .zip), պահվածկ (.sav) կամ «GBA BIOS» (gba_bios.bin)",
    "You can also drag & drop a ROM/save file to load it", "Կարող եք նաև քաշել և թողնել որևէ ROM թե պահվածկ՝ այն տեղադրելու համար",
    "Open ROM", "Բացեք «ROM»",
    ICON_FK_CLOCK_O " Load Recently Played Game", ICON_FK_CLOCK_O " Տեղադրեք Վերջերս Խաղացված",
    ICON_FK_DOWNLOAD " Export Save", ICON_FK_DOWNLOAD  "Արտահանեք Պահվածկ",
    "No recently played games", "Վերջերս խաղարկված չկա:",
    ICON_FK_GAMEPAD " Controllers", ICON_FK_GAMEPAD " Կարգավորիչներ",
    "Controller", "Կարգավորիչն",
    "No Controller", "Կարգավորող Չկա",
    "Reset Default Controller Bindings", "Վերականգնել լռելյայն Կարգավորողի կապերը",
    "Rumble Supported", "Կշարողանում Է Դղրդալ",
    "Rumble Not Supported", "Չի Կարող Դղրդալ",
    ICON_FK_FLOPPY_O " Save States", ICON_FK_FLOPPY_O " Պահման Վիճակներ",
    "Save Slot %d", "Պահման %d",
    "Capture", "Նկարեք",
    "Restore", "Վերա.",
    "This save state came from an incompatible build. SkyEmu has attempted to recover it, but there may be issues", "这个即时存档来自一个不兼容的构建. SkyEmu 已经尝试恢复, 但可能会有问题",
    ICON_FK_DESKTOP " Display Settings", ICON_FK_DESKTOP " Էկրանաին Կարգավորումներ",
    "Screen Shader", "Էկրանի Նկարիչ",
    "Pixelate\0Bilinear\0LCD\0LCD & Subpixels\0Smooth Upscale (xBRZ)\0", "Դիսկրետ\0Երկգծային\0«LCD»\0«LCD» և ենթակետներ\0Հարթ Բարձրակարգ (xBRZ)\0",
    "Screen Rotation", "Էկրանաին Ռոտացիա",
    "0 degrees\00090 degrees\000180 degrees\000270 degrees\0", "0 աստիճան\00090 աստիճան\000180 աստիճան\000270 աստիճան\0",
    "Color Correction", "Գույնաին Ոլղղում",
    "Strength: %.2f", "Ուժ: %.2f",
    "Screen Ghosting", "Էկրանաին Ժամանակավոր Ստվեր",
    "Force Integer Scaling", "Ստիպեք Ամբողջական չափսեր",
    "Stretch Screen to Fit", "Ձգեք էկրանը հարմարեցնելու համար",
    "Game Boy Color Palette", "Գունավոր գունապնակ «Game Boy Color»-ի համար",
    "GB Palette %d", "GB 调色板 %d",
    "Reset Palette to Defaults", "重置调色板默认值",
    ICON_FK_KEYBOARD_O " Keybinds", ICON_FK_KEYBOARD_O " 键盘快捷键",
    "Reset Default Keybinds", "重置键盘快捷键默认值",
    ICON_FK_WRENCH " Advanced",ICON_FK_WRENCH " 高级",
    "Light Mode", "浅色模式",
    "Show Debug Tools", "显示调试工具",
    "Adjust volume", "调节音量",
    "Show/Hide Menu Panel", "显示/隐藏菜单面板",
    "Rewind at 8x speed", "以8倍速度倒带",
    "Rewind at 4x speed", "以4倍速度倒带",
    "Toggle pause/play.\n When paused, the rom selection screen will be shown.", "切换暂停/游玩.\n 暂停时, 屏幕显示选择 rom 菜单.",
    "Run at 2x Speed", "以2倍速度快进",
    "Run at the fastest speed possible", "速度无限制快进",
    "Screen", "屏幕",
    "LCD Shader Init", "LCD 着色器初始化",
    "Menu", "菜单",
    "Copy as..", "复制..",
    "Current", "当前",
    "Original", "原始",
    "Opacity", "不透明度",
    ICON_FK_HAND_O_RIGHT " Touch Control Settings", ICON_FK_HAND_O_RIGHT " 触摸控制设置",
    "Hide when inactive", "不活动时隐藏",
    ICON_FK_FILE_O " Dump Memory to File", ICON_FK_FILE_O " 转储内存文件",
    "Start Address", "起始地址",
    "Size", "大小",
    "Save Memory Dump", "保存转储内存",
    ICON_FK_RANDOM " Last Branch Locations", ICON_FK_RANDOM " 最后分支位置",
    "Opacity: %.2f", "不透明度: %.2f",
    "Step Instruction", "步进指令",
    "Disconnect Log", "断开日志",
    ICON_FK_FOLDER_OPEN " Open File From Disk", ICON_FK_FOLDER_OPEN " 从磁盘打开文件",
    "Exit File Browser", "退出文件浏览",
    "Go back to recently loaded games", "返回最近载入的游戏",
    "Go to parent directory", "转到上级目录",
    "UP", "上",
    "DOWN", "下",
    "LEFT", "左",
    "RIGHT", "右",
    "Reset Game", "重置游戏",
    "Turbo A", "连发 A",
    "Turbo B", "连发 B",
    "Turbo X", "连发 X",
    "Turbo Y", "连发 Y",
    "Turbo L", "连发 L",
    "Turbo R", "连发 R",
    "Solar Sensor+", "太阳能传感器+",
    "Solar Sensor-", "太阳能传感器-",
    "Theme", "主题",
    "Solar Sensor", "太阳能传感器",
    "Brightness: %.2f", "亮度: %.2f",
    "Dark\0Light\0Black\0", "深色\0浅色\0黑色\0",
    "Always Show Menu/Nav Bar", "始终显示菜单/导航栏",
    "Language", "语言",

    "SPACE", "空格",
    "ESCAPE", "ESC",
    "ENTER", "回车",
    "BACKSPACE", "退格键",
    "INSERT", "插入",
    "DELETE", "删除",
    "RIGHT", "右",
    "LEFT", "左",
    "DOWN", "下",
    "UP", "上",
    "LEFT_SHIFT", "左 Shift",
    "LEFT_CONTROL", "左 Control",
    "LEFT_ALT", "左 Alt",
    "LEFT_SUPER", "左 Super",
    "RIGHT_SHIFT", "右 Shift",
    "RIGHT_CONTROL", "右 Control",
    "RIGHT_ALT", "右 Alt",
    "RIGHT_SUPER", "右 Super",
    "MENU", "菜单",
    "Enable Turbo and Hold Button Modifiers", "TRANSLATE ME",
    "Scale", "TRANSLATE ME",
    "Scale: %.2f","TRANSLATE %.2f",
    "GBA Color Correction Type","TRANSLATE ME",
    ICON_FK_TEXT_HEIGHT " GUI",ICON_FK_TEXT_HEIGHT " TBD",
    "Full Screen","TBD",
    ICON_FK_CODE_FORK " Additional Search Paths",ICON_FK_CODE_FORK " TBD",
    "Save File/State Path","TBD",
    "BIOS/Firmware Path","TBD",
    "Create new save files in Save Path","TBD",
    ICON_FK_CROSSHAIRS " Located BIOS/Firmware Files",ICON_FK_CROSSHAIRS " TBD",
    "Force GB games to run in DMG mode","TBD",
    "Enable HTTP Control Server","TBD",
    "Server Port","TBD",
    "Toggle Full Screen","TBD",
    NULL,NULL
};

const char ** localization_map=NULL;
size_t localization_size=0;
int se_localize_cmp(const void *a, const void*b){return strcmp(((const char**)a)[0],((const char**)b)[0]);}
void se_set_language(int language_enum){
    const char ** new_map = NULL; 
    if(language_enum==SE_LANG_CHINESE)new_map = zh_localization_array; 
    if(language_enum==SE_LANG_ARMENIAN)new_map = hy_localization_array; 
    if(new_map!=localization_map){
        localization_map=new_map;
        localization_size=0;
        if(localization_map){
            while(localization_map[localization_size*2])++localization_size;
            qsort(localization_map,localization_size,sizeof(const char*)*2,se_localize_cmp);
        }
    }
}
const char* se_language_string(int language_enum){
    switch (language_enum){
        case SE_LANG_DEFAULT: return se_localize("Default");
        case SE_LANG_ENGLISH: return "English";
        case SE_LANG_CHINESE: return "中文";
        case SE_LANG_ARMENIAN: return "Հայերեն";
    }
    return "";
}
const char* se_localize(const char* string){
    if(localization_map==NULL)return string; 
    const char** result = (const char**)bsearch(&string,localization_map,localization_size,sizeof(const char*)*2,se_localize_cmp);
    if(!result)return string;
    else return result[1];
}
