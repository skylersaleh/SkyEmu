#include "localization.h"
#include "IconsForkAwesome.h"
#include "stdlib.h"
#include <ctype.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>

#if defined(PLATFORM_IOS) || defined(PLATFORM_MACOS)
#include <CoreFoundation/CoreFoundation.h>
#endif

// Strings added in v3 requiring translation:
// - "Avoid NDS Touchscreen"
// - ICON_FK_PLUS " New"
// - "Create new files in path" (which replaced "Create new save files in Save
// Path")
// - ICON_FK_KEY " Action Replay Codes" (optional)
// - "Cheat Code Path"

// Strings added in v4 requiring translation:
// - "Disabled in Hardcore Mode"
// - "Rewind"
// - "Slow"
// - "Fast Forward"

// #define SHOW_TRANSLATE_ME 1

// Special thanks to https://github.com/shooterspps and Nilay for the Chinese
// Translation
static char *zh_localization_array[] = {
    ICON_FK_FILE_O " Load Game", ICON_FK_FILE_O " 载入游戏", "Up", "上", "Down",
    "下", "Left", "左", "Right", "右", "Start", "开始", "Select", "选择",
    "Fold Screen (NDS)", "折叠屏幕 (NDS)", "Tap Screen (NDS)", "点击屏幕 (NDS)",
    "Emulator " ICON_FK_PAUSE "/" ICON_FK_PLAY,
    "模拟器 " ICON_FK_PAUSE "/" ICON_FK_PLAY, "Emulator " ICON_FK_BACKWARD,
    "模拟器 " ICON_FK_BACKWARD, "Emulator " ICON_FK_FORWARD,
    "模拟器 " ICON_FK_FORWARD, "Emulator " ICON_FK_FAST_FORWARD,
    "模拟器 " ICON_FK_FAST_FORWARD, "Capture State 0", "即时存档 0",
    "Restore State 0", "即时读档 0", "Capture State 1", "即时存档 1",
    "Restore State 1", "即时读档 1", "Capture State 2", "即时存档 2",
    "Restore State 2", "即时读档 2", "Capture State 3", "即时存档 3",
    "Restore State 3", "即时读档 3", "Analog Up/Down", "摇杆 上/下",
    "Analog Left/Right", "摇杆 左/右", "Analog L", "扳机 L", "Analog R",
    "扳机 R", "Display FPS: %2.1f\n", "显示屏 FPS: %2.1f\n",
    "Emulation FPS: %2.1f\n", "模拟器 FPS: %2.1f\n", ICON_FK_VOLUME_UP " Audio",
    ICON_FK_VOLUME_UP " 音频", "Left Audio Channel", "音频左声道",
    "Right Audio Channel", "音频右声道", "Channel 0", "声道 0", "Channel 1",
    "声道 1", "Channel 2", "声道 2", "Channel 3", "声道 3", "Channel 4",
    "声道 4", "Channel 5", "声道 5", "Channel 6", "声道 6", "Channel 7",
    "声道 7", "Channel 8", "声道 8", "Channel 9", "声道 9", "Channel A",
    "声道 A", "Channel B", "声道 B", "Channel C", "声道 C", "Channel D",
    "声道 D", "Channel E", "声道 E", "Channel F", "声道 F",
    "Channel 1 (Square)", "声道 1 (方形)", "Channel 2 (Square)",
    "声道 2 (方形)", "Channel 3 (Wave)", "声道 3 (波形)", "Channel 4 (Noise)",
    "声道 4 (噪声)", "Channel A (FIFO)", "声道 A (FIFO)", "Channel B (FIFO)",
    "声道 B (FIFO)", "Audio Ring (Samples Available: %d)",
    "音频环绕 (可用采样: %d)", "Audio Watchdog Triggered %d Times",
    "音频定时触发 %d 时间", ICON_FK_INFO_CIRCLE " Build Info",
    ICON_FK_INFO_CIRCLE " 构建信息",
    "Commit Hash:", "哈希值提交:", ICON_FK_SERVER " Registers",
    ICON_FK_SERVER " 寄存器", ICON_FK_LIST_OL " Disassembly",
    ICON_FK_LIST_OL " 反汇编", ICON_FK_EXCHANGE " Read/Write Memory Address",
    ICON_FK_EXCHANGE " 读/写内存地址", "address", "地址", "data (32 bit)",
    "数据 (32 bit)", "data (16 bit)", "数据 (16 bit)", "data (8 bit)",
    "数据 (8 bit)", "data (signed 32b)", "数据 (写入 32b)", "data (signed 16b)",
    "数据 (写入 16b)", "data (signed 8b)", "数据 (写入 8b)",
    ICON_FK_PENCIL_SQUARE_O " Memory", ICON_FK_PENCIL_SQUARE_O " 内存",
    ICON_FK_AREA_CHART " Emulator Stats", ICON_FK_AREA_CHART " 模拟器统计",
    "Show/Hide %s Panel\n", "显示/隐藏 %s面板\n",
    "Press new button " ICON_FK_SIGN_IN, "按下按键 " ICON_FK_SIGN_IN,
    "Move Axis ", "移动轴 ", "Not bound", "不绑定", "Hat %d %s", "方向 %d %s",
    "Analog %d %s", "手柄轴 %d %s", "Key %d", "按键 %d", "Analog %d (%0.2f)",
    "手柄轴 %d (%0.2f)", "Load ROM from file (.gb, .gbc, .gba, .zip)",
    "从文件中载入 ROM (.gb, .gbc, .gba, .zip)",
    "You can also drag & drop a ROM to load it", "你也可以通过拖放载入一个 ROM",
    "Load ROM(.gb, .gbc, .gba, .zip), save(.sav), or GBA bios (gba_bios.bin) "
    "from file",
    "从文件中载入 ROM(.gb, .gbc, .gba, .zip), save(.sav), 或 GBA bios "
    "(gba_bios.bin)",
    "You can also drag & drop a ROM/save file to load it",
    "你也可以通过拖放载入一个 ROM/存档文件", "Open ROM", "打开 ROM",
    ICON_FK_CLOCK_O " Load Recently Played Game",
    ICON_FK_CLOCK_O " 载入最近玩过的游戏", ICON_FK_DOWNLOAD " Export Save",
    ICON_FK_DOWNLOAD " 导出存档", "No recently played games",
    "最近没有玩过游戏", ICON_FK_GAMEPAD " Controllers",
    ICON_FK_GAMEPAD " 控制器", "Controller", "控制器", "No Controller",
    "无控制器", "Reset Default Controller Bindings", "重置控制器默认绑定",
    "Rumble Supported", "支持震动", "Rumble Not Supported", "不支持震动",
    ICON_FK_FLOPPY_O " Save States", ICON_FK_FLOPPY_O " 即时存档",
    "Save Slot %d", "存档位置 %d", "Capture", "存档", "Restore", "读档",
    "This save state came from an incompatible build. SkyEmu has attempted to "
    "recover it, but there may be issues",
    "这个即时存档来自一个不兼容的构建. SkyEmu 已经尝试恢复, 但可能会有问题",
    ICON_FK_DESKTOP " Display Settings", ICON_FK_DESKTOP " 显示设置",
    "Screen Shader", "屏幕着色器",
    "Pixelate\0Bilinear\0LCD\0LCD & Subpixels\0Smooth Upscale (xBRZ)\0",
    "像素化\0双线性\0LCD\0LCD & 子像素\0高级平滑过滤 (xBRZ)\0",
    "Screen Rotation", "屏幕旋转",
    "0 degrees\00090 degrees\000180 degrees\000270 degrees\0",
    "0°\00090°\000180°\000270°\0", "Color Correction", "颜色校正",
    "Strength: %.2f", "强度: %.2f", "Screen Ghosting", "屏幕残影",
    "Force Integer Scaling", "强制整数缩放", "Stretch Screen to Fit",
    "拉伸适应屏幕", "Game Boy Color Palette", "Game Boy Color 调色板",
    "GB Palette %d", "GB 调色板 %d", "Reset Palette to Defaults",
    "重置调色板默认值", ICON_FK_KEYBOARD_O " Keybinds",
    ICON_FK_KEYBOARD_O " 键盘快捷键", "Reset Default Keybinds",
    "重置键盘快捷键默认值", ICON_FK_WRENCH " Advanced", ICON_FK_WRENCH " 高级",
    "Light Mode", "浅色模式", "Show Debug Tools", "显示调试工具",
    "Adjust volume", "调节音量", "Show/Hide Menu Panel", "显示/隐藏菜单面板",
    "Rewind at 8x speed", "以8倍速度倒带", "Rewind at 4x speed",
    "以4倍速度倒带",
    "Toggle pause/play.\n When paused, the rom selection screen will be shown.",
    "切换暂停/游玩.\n 暂停时, 屏幕显示选择 rom 菜单.", "Run at 2x Speed",
    "以2倍速度快进", "Run at the fastest speed possible", "速度无限制快进",
    "Screen", "屏幕", "LCD Shader Init", "LCD 着色器初始化", "Menu", "菜单",
    "Copy as..", "复制..", "Current", "当前", "Original", "原始", "Opacity",
    "不透明度", ICON_FK_HAND_O_RIGHT " Touch Control Settings",
    ICON_FK_HAND_O_RIGHT " 触摸控制设置", "Hide when inactive", "不活动时隐藏",
    ICON_FK_FILE_O " Dump Memory to File", ICON_FK_FILE_O " 转储内存文件",
    "Start Address", "起始地址", "Size", "大小", "Save Memory Dump",
    "保存转储内存", ICON_FK_RANDOM " Last Branch Locations",
    ICON_FK_RANDOM " 最后分支位置", "Opacity: %.2f", "不透明度: %.2f",
    "Step Instruction", "步进指令", "Disconnect Log", "断开日志",
    ICON_FK_FOLDER_OPEN " Open File From Disk",
    ICON_FK_FOLDER_OPEN " 从磁盘打开文件", "Exit File Browser", "退出文件浏览",
    "Go back to recently loaded games", "返回最近载入的游戏",
    "Go to parent directory", "转到上级目录", "UP", "上", "DOWN", "下", "LEFT",
    "左", "RIGHT", "右", "Reset Game", "重置游戏", "Turbo A", "连发 A",
    "Turbo B", "连发 B", "Turbo X", "连发 X", "Turbo Y", "连发 Y", "Turbo L",
    "连发 L", "Turbo R", "连发 R", "Solar Sensor+", "太阳能传感器+",
    "Solar Sensor-", "太阳能传感器-", "Theme", "主题", "Solar Sensor",
    "太阳能传感器", "Brightness: %.2f", "亮度: %.2f", "Dark\0Light\0Black\0",
    "深色\0浅色\0黑色\0", "Always Show Menu/Nav Bar", "始终显示菜单/导航栏",
    "Language", "语言",

    "SPACE", "空格", "ESCAPE", "ESC", "ENTER", "回车", "BACKSPACE", "退格键",
    "INSERT", "插入", "DELETE", "删除", "RIGHT", "右", "LEFT", "左", "DOWN",
    "下", "UP", "上", "LEFT_SHIFT", "左 Shift", "LEFT_CONTROL", "左 Control",
    "LEFT_ALT", "左 Alt", "LEFT_SUPER", "左 Super", "RIGHT_SHIFT", "右 Shift",
    "RIGHT_CONTROL", "右 Control", "RIGHT_ALT", "右 Alt", "RIGHT_SUPER",
    "右 Super", "MENU", "菜单", "Enable Turbo and Hold Button Modifiers",
    "启用按住按键连发", "Scale", "缩放", "Scale: %.2f", "缩放 %.2f",
    "GBA Color Correction Type", "GBA 颜色校正类型", ICON_FK_TEXT_HEIGHT " GUI",
    ICON_FK_TEXT_HEIGHT " 界面", "Full Screen", "全屏",
    ICON_FK_CODE_FORK " Additional Search Paths",
    ICON_FK_CODE_FORK " 额外搜索路径", "Save File/State Path",
    "即时存档/文件路径", "BIOS/Firmware Path", "BIOS/固件路径",
    "Create new save files in Save Path", "在存档路径中创建新的存档文件",
    ICON_FK_CROSSHAIRS " Located BIOS/Firmware Files",
    ICON_FK_CROSSHAIRS " BIOS/固件文件位置",
    "Force GB games to run in DMG mode", "强制在 DMG 模式下运行 GB 游戏",
    "Enable HTTP Control Server", "启用 HTTP 服务器控制", "Server Port",
    "服务器端口", "Toggle Full Screen", "切换全屏",
    // Strings added in V3
    "Avoid NDS Touchscreen", "避开NDS触屏", ICON_FK_PLUS " New",
    ICON_FK_PLUS " 新建", ICON_FK_KEY " Action Replay Codes",
    ICON_FK_KEY " Action Replay 代码", "Create new files in paths",
    "在路径中创建新文件", "Cheat Code Path", "作弊码路径", NULL, NULL};

// Armenian translation by https://github.com/udxs
static char *hy_localization_array[] = {
    ICON_FK_FILE_O " Load Game", ICON_FK_FILE_O " Տեղադրեք Խաղ", "Up", "Վերև",
    "Down", "Ներքև", "Left", "Ձախ", "Right", "Աջ", "Start", "Սկսեք", "Select",
    "Ընտրեք", "Fold Screen (NDS)", "Ծալեք Էկր. (NDS)", "Tap Screen (NDS)",
    "Հպեք Էկր. (NDS)", "Emulator " ICON_FK_PAUSE "/" ICON_FK_PLAY,
    "Վերարտադ. " ICON_FK_PAUSE "/" ICON_FK_PLAY, "Emulator " ICON_FK_BACKWARD,
    "Վերարտադ. " ICON_FK_BACKWARD, "Emulator " ICON_FK_FORWARD,
    "Վերարտադ. " ICON_FK_FORWARD, "Emulator " ICON_FK_FAST_FORWARD,
    "Վերարտադ. " ICON_FK_FAST_FORWARD, "Capture State 0", "Նկարեք Վիճակը 0",
    "Restore State 0", "Վերա. Վիճակը 0", "Capture State 1", "Նկարեք Վիճակը 1",
    "Restore State 1", "Վերա. Վիճակը 1", "Capture State 2", "Նկարեք Վիճակը 2",
    "Restore State 2", "Վերա. Վիճակը 2", "Capture State 3", "Նկարեք Վիճակը 3",
    "Restore State 3", "Վերա, Վիճակը 3", "Analog Up/Down",
    "Անալոգային Վերև/Ներքև", "Analog Left/Right", "Անալոգային Ձախ/Աջ",
    "Analog L", "Անալոգային L", "Analog R", "Անալոգային R",
    "Display FPS: %2.1f\n", "Էկրանի Թարմացումն Վայրկյանում. %2.1f\n",
    "Emulation FPS: %2.1f\n", "Հաշվողական Թարմացում Վայրկյանում. %2.1f\n",
    ICON_FK_VOLUME_UP " Audio", ICON_FK_VOLUME_UP " Ձայն", "Left Audio Channel",
    "Ձախ Ձայնային Ալիք", "Right Audio Channel", "Աջ Ձայնային Ալիք", "Channel 0",
    "Ալիք 0", "Channel 1", "Ալիք 1", "Channel 2", "Ալիք 2", "Channel 3",
    "Ալիք 3", "Channel 4", "Ալիք 4", "Channel 5", "Ալիք 5", "Channel 6",
    "Ալիք 6", "Channel 7", "Ալիք 7", "Channel 8", "Ալիք 8", "Channel 9",
    "Ալիք 9", "Channel A", "Ալիք A", "Channel B", "Ալիք B", "Channel C",
    "Ալիք C", "Channel D", "Ալիք D", "Channel E", "Ալիք E", "Channel F",
    "Ալիք F", "Channel 1 (Square)", "Ալիք 1 (Քառակուսի)", "Channel 2 (Square)",
    "Ալիք 2 (Քառակուսի)", "Channel 3 (Wave)", "Ալիք 3 (Ալիք)",
    "Channel 4 (Noise)", "Ալիք 4 (Աղմուկ)", "Channel A (FIFO)", "Ալիք A (FIFO)",
    "Channel B (FIFO)", "Ալիք B (FIFO)", "Audio Ring (Samples Available: %d)",
    "Ձայնային Օղակ (Մնացած Վանկերը. %d)", "Audio Watchdog Triggered %d Times",
    "Ձայնային Ժամապահը Գործարկվել է %d Անգամ",
    ICON_FK_INFO_CIRCLE " Build Info",
    ICON_FK_INFO_CIRCLE " Կառուցման Տեղեկատվություն",
    "Commit Hash:", "«Git» Վերսիա տարբերակը.", ICON_FK_SERVER " Registers",
    ICON_FK_SERVER " Ռեգիստրներ", ICON_FK_LIST_OL " Disassembly",
    ICON_FK_LIST_OL " Ապակառուցում",
    ICON_FK_EXCHANGE " Read/Write Memory Address",
    ICON_FK_EXCHANGE " Կարդեք/Գրեք Հիշողության Հասցեները", "address", "հասցեն",
    "data (32 bit)", "տվյալներ (32 բիթ)", "data (16 bit)", "տվյալներ (16 բիթ)",
    "data (8 bit)", "տվյալներ (8 բիթ)", "data (signed 32b)", "տվյալներ (բ 32բ)",
    "data (signed 16b)", "տվյալներ (բ 16բ)", "data (signed 8b)",
    "տվյալներ (բ 8բ)", ICON_FK_PENCIL_SQUARE_O " Memory",
    ICON_FK_PENCIL_SQUARE_O " Հիշողություն",
    ICON_FK_AREA_CHART " Emulator Stats",
    ICON_FK_AREA_CHART " Սիմուլյատորի Վիճակագրություն", "Show/Hide %s Panel\n",
    "Ցույց տվեք/թաքցնվեք %s վահանակը\n", "Press new button " ICON_FK_SIGN_IN,
    " Սեղմեք նոր կոճակ" ICON_FK_SIGN_IN, "Move Axis ", "Տեղափոխեք Առանցքը",
    "Not bound", "Անկապված", "Hat %d %s", "Ուղղորդող %d %s", "Analog %d %s",
    "Անալոգ %d %s", "Key %d", "Կոճակ %d", "Analog %d (%0.2f)",
    "Անալոգ %d (%0.2f)", "Load ROM from file (.gb, .gbc, .gba, .zip)",
    "Տեղադրեք ROM-ը (.gb, .gbc, .gba, .zip)",
    "You can also drag & drop a ROM to load it",
    "Կարող եք նաև քաշել և թողնել որևէ ROM՝ այն տեղադրելու համար",
    "Load ROM(.gb, .gbc, .gba, .zip), save(.sav), or GBA bios (gba_bios.bin) "
    "from file",
    "Տեղադրելու ROM (.gb, .gbc, .gba, .zip), պահվածկ (.sav) կամ «GBA BIOS» "
    "(gba_bios.bin)",
    "You can also drag & drop a ROM/save file to load it",
    "Կարող եք նաև քաշել և թողնել որևէ ROM թե պահվածկ՝ այն տեղադրելու համար",
    "Open ROM", "Բացեք «ROM»", ICON_FK_CLOCK_O " Load Recently Played Game",
    ICON_FK_CLOCK_O " Տեղադրեք Վերջերս Խաղացված",
    ICON_FK_DOWNLOAD " Export Save", ICON_FK_DOWNLOAD "Արտահանեք Պահվածկ",
    "No recently played games",
    "Վերջերս խաղարկված չկա:", ICON_FK_GAMEPAD " Controllers",
    ICON_FK_GAMEPAD " Կարգավորիչներ", "Controller", "Կարգավորիչն",
    "No Controller", "Կարգավորող Չկա", "Reset Default Controller Bindings",
    "Վերականգնեք լռելյայն Կարգավորողի կապերը", "Rumble Supported",
    "Կշարողանում Է Դղրդալ", "Rumble Not Supported", "Չի Կարող Դղրդալ",
    ICON_FK_FLOPPY_O " Save States", ICON_FK_FLOPPY_O " Պահման Վիճակներ",
    "Save Slot %d", "Պահման %d", "Capture", "Նկարեք", "Restore", "Վերա.",
    "This save state came from an incompatible build. SkyEmu has attempted to "
    "recover it, but there may be issues",
    "Այս Պահվածկէ առաջացել է անհամատեղելի Վերսիաից: SkyEmu-ն կփորձի "
    "վերականգնել այն, բայց կարող են խնդիրներ լինել:",
    ICON_FK_DESKTOP " Display Settings",
    ICON_FK_DESKTOP " Էկրանաին Կարգավորումներ", "Screen Shader",
    "Էկրանի Նկարիչ",
    "Pixelate\0Bilinear\0LCD\0LCD & Subpixels\0Smooth Upscale (xBRZ)\0",
    "Դիսկրետ\0Երկգծային\0«LCD»\0«LCD» և ենթակետներ\0Հարթ Բարձրակարգ (xBRZ)\0",
    "Screen Rotation", "Էկրանաին Ռոտացիա",
    "0 degrees\00090 degrees\000180 degrees\000270 degrees\0",
    "0 աստիճան\00090 աստիճան\000180 աստիճան\000270 աստիճան\0",
    "Color Correction", "Գույնաին Ոլղղում", "Strength: %.2f", "Ուժ. %.2f",
    "Screen Ghosting", "Էկրանաին Ժամանակավոր Ստվեր", "Force Integer Scaling",
    "Ստիպեք Ամբողջական չափսեր", "Stretch Screen to Fit",
    "Ձգեք էկրանը հարմարեցնելու համար", "Game Boy Color Palette",
    "Գունավոր գունապնակ «Game Boy Color»-ի համար", "GB Palette %d",
    "GB-ի Գունա. %d", "Reset Palette to Defaults",
    "Վերականգնեք Լռելյայն Գունապնակը", ICON_FK_KEYBOARD_O " Keybinds",
    ICON_FK_KEYBOARD_O " Կոճակների Կապերը", "Reset Default Keybinds",
    "Վերականգնեք Կոճակների Լռելյայն Կապերը", ICON_FK_WRENCH " Advanced",
    ICON_FK_WRENCH " Բարդ", "Light Mode", "Լույսի թեմա", "Show Debug Tools",
    "Ցույց Տվեք Ինժեներական Գործիքները", "Adjust volume",
    "Կարգավորեք ձայնի ծավալը", "Show/Hide Menu Panel",
    "Ցույց տվեք/թաքցնվեք մենյուի վահանակը", "Rewind at 8x speed",
    "Հետ պտտեք 8x արագությամբ", "Rewind at 4x speed",
    "Հետ պտտեք 4x արագությամբ",
    "Toggle pause/play.\n When paused, the rom selection screen will be shown.",
    "Դադարեք թե Խաղեք:\n Դադարեցնելու դեպքում ROM-ի ընտրության էկրանը "
    "կցուցադրվի:",
    "Run at 2x Speed", "Խաղացեք 2x արագությամբ",
    "Run at the fastest speed possible",
    "Խաղացեք հնարավոր ամենաարագ արագությամբ", "Screen", "Էկրան",
    "LCD Shader Init", "«LCD»-ի Նկարիչ Գործարկում", "Menu", "Մենյու",
    "Copy as..", "Պատճենել որպես...", "Current", "Ընթացիկը", "Original",
    "Բնօրինակը", "Opacity", "Անթափանցիկություն",
    ICON_FK_HAND_O_RIGHT " Touch Control Settings",
    ICON_FK_HAND_O_RIGHT " Հպման Կառավարման Կարգավորումներ",
    "Hide when inactive", "Թաքցնեք երբ ոչ ակտիվ է",
    ICON_FK_FILE_O " Dump Memory to File",
    ICON_FK_FILE_O " Հիշողությունը Լցնել Ֆայլին", "Start Address",
    "Սկիզբ Հասցե", "Size", "Չափը", "Save Memory Dump", "Պահպանեք Հիշողությունը",
    ICON_FK_RANDOM " Last Branch Locations",
    ICON_FK_RANDOM " Վերջին Մասնաճյուղի Վայրերը", "Opacity: %.2f",
    "Անթափանցիկություն. %.2f", "Step Instruction", "Քայլեք Մեկ հրահանգով",
    "Step Frame", "Քայլեք Մեկ Շրջանակէ", "Disconnect Log",
    "Անջատել Գրանցամատյանը", ICON_FK_FOLDER_OPEN " Open File From Disk",
    ICON_FK_FOLDER_OPEN " Բացեք ֆայլ", "Exit File Browser",
    "Դուրս եկեք ֆայլերի դիտիչից", "Go back to recently loaded games",
    "Վերադարձիք դեպի վերջերս խաղացած խաղեր", "Go to parent directory",
    "Գնացեք վերին գրացուցակ", "UP", "ՎԵՐԵՒ", "DOWN", "ՆԵՐՔԵՒ", "LEFT", "ՁԱԽ",
    "RIGHT", "ԱՋ", "Reset Game", "Վերականգնեք", "Turbo A", "Տուրբո A",
    "Turbo B", "Տուրբո B", "Turbo X", "Տուրբո X", "Turbo Y", "Տուրբո Y",
    "Turbo L", "Տուրբո L", "Turbo R", "Տուրբո R", "Solar Sensor+",
    "Արևային Ցուցիչ +", "Solar Sensor-", "Արևային Ցուցիչ -", "Theme", "Թեմա",
    "Solar Sensor", "Արևային Ցուցիչ", "Brightness: %.2f", "Պայծառություն. %.2f",
    "Dark\0Light\0Black\0", "Մթնած\0Լուսապայտ\0Սեվ\0",
    "Always Show Menu/Nav Bar", "Միշտ Ցուցադրեք Նավարկ./Մենյուի Գիծը",
    "Language", "Լեզու", "SPACE", "ՏԻԵԶԵՐՔ", "ESCAPE", "ESC", "ENTER",
    "ՄՈՒՏՔԱԳՐԵՔ", "BACKSPACE", "BACKSPACE", "INSERT", "INSERT", "DELETE",
    "DELETE", "RIGHT", "ԱՋ", "LEFT", "ՁԱԽ", "DOWN", "ՆԵՐՔԵՒ", "UP", "ՎԵՐԵՒ",
    "LEFT_SHIFT", "Ձախ Shift", "LEFT_CONTROL", "Ձախ Control", "LEFT_ALT",
    "Ձախ Alt", "LEFT_SUPER", "Ձախ Super", "RIGHT_SHIFT", "Աջ Shift",
    "RIGHT_CONTROL", "Աջ Control", "RIGHT_ALT", "Աջ Alt", "RIGHT_SUPER",
    "Աջ Super", "MENU", "ՄԵՆՅՈՒ", "Enable Turbo and Hold Button Modifiers",
    "Միացնեք Տուրբո և Մոդիֆիկատորների Կոճակները", "Scale", "Չափս",
    "Scale: %.2f", "Չափս %.2f", "GBA Color Correction Type",
    "Գույնի Ուղղման Տեսակը", ICON_FK_TEXT_HEIGHT " GUI",
    ICON_FK_TEXT_HEIGHT " Միջերես", "Full Screen", "Ամբողջ էկրանով",
    ICON_FK_CODE_FORK " Additional Search Paths",
    ICON_FK_CODE_FORK " Լրացուցիչ Փնտրելու Վայրեր", "Save File/State Path",
    "Պահպանեք Վայրերը", "BIOS/Firmware Path", "BIOS/Որոնվածը Վայրը",
    "Create new save files in Save Path",
    "Ստեղծեք նոր պահպանման ֆայլեր Պահպանել Վայրը",
    ICON_FK_CROSSHAIRS " Located BIOS/Firmware Files",
    ICON_FK_CROSSHAIRS " BIOS/Որոնվածը Ֆայլեր",
    "Force GB games to run in DMG mode",
    "Ստիպել «ԳԲ» խաղերին աշխատել «DMG» ռեժիմով", "Enable HTTP Control Server",
    "Միացնեք «HTTP» Կառավարման Սերվերը", "Server Port", "Սերվերի Պորտ",
    "Toggle Full Screen", "Ամբողջ էկրանը",
    "Can't find all needed BIOS/Boot ROM/Firmware Files.",
    "Չենք կարող գտնել բոլոր անհրաժեշտ\nBIOS/Գործարկման ROM/Որոնվածային "
    "ֆայլերը:",
    "Accuracy will suffer and some features won't work.",
    "Ճշգրտությունը կտուժի\nև որոշ գործառույթներ չեն աշխատի:",
    // New in v3
    "Avoid NDS Touchscreen", "Մի ծածկեք NDS-ի էկրանը կառավարիչներով",
    ICON_FK_PLUS " New", ICON_FK_PLUS "Ավելացնեք",
    ICON_FK_KEY " Action Replay Codes", ICON_FK_KEY " «Action Replay» Կոդեր",
    "Create new files in paths", "Ստեղծեք նոր ֆայլեր ուղիներով",
    "Cheat Code Path", "Խաբել Կոդը Ուղին",

    NULL, NULL};

// Greek translation by https://github.com/OFFTKP
static char *gr_localization_array[] = {
    ICON_FK_FILE_O " Load Game", ICON_FK_FILE_O " Φόρτωση Παιχνιδιού", "Up",
    "Πάνω", "Down", "Κάτω", "Left", "Αριστερά", "Right", "Δεξιά", "Start",
    "Εκκίνηση", "Select", "Επιλογή", "Fold Screen (NDS)", "Δίπλωμα Οθ. (NDS)",
    "Tap Screen (NDS)", "Άγγιγμα Οθ. (NDS)",
    "Emulator " ICON_FK_PAUSE "/" ICON_FK_PLAY,
    "Εξομοιωτής " ICON_FK_PAUSE "/" ICON_FK_PLAY, "Emulator " ICON_FK_BACKWARD,
    "Εξομοιωτής " ICON_FK_BACKWARD, "Emulator " ICON_FK_FORWARD,
    "Εξομοιωτής " ICON_FK_FORWARD, "Emulator " ICON_FK_FAST_FORWARD,
    "Εξομοιωτής " ICON_FK_FAST_FORWARD, "Capture State 0", "Αποθήκ. Κατάστ. 0",
    "Restore State 0", "Φόρτωση Κατάστ. 0", "Capture State 1",
    "Αποθήκ. Κατάστ. 1", "Restore State 1", "Φόρτωση Κατάστ. 1",
    "Capture State 2", "Αποθήκ. Κατάστ. 2", "Restore State 2",
    "Φόρτωση Κατάστ. 2", "Capture State 3", "Αποθήκ. Κατάστ. 3",
    "Restore State 3", "Φόρτωση Κατάστ. 3", "Analog Up/Down",
    "Αναλογικό Πάνω/Κάτω", "Analog Left/Right", "Αναλογικό Αριστερά/Δεξιά",
    "Analog L", "Αναλογικό L", "Analog R", "Αναλογικό R",
    "Display FPS: %2.1f\n", "Καρέ ανά δευτερόλεπτο οθόνης: %2.1f\n",
    "Emulation FPS: %2.1f\n", "Καρέ ανά δευτερόλεπτο εξομοίωσης: %2.1f\n",
    ICON_FK_VOLUME_UP " Audio", ICON_FK_VOLUME_UP " Ήχος", "Left Audio Channel",
    "Αριστερό Κανάλι Ήχου", "Right Audio Channel", "Δεξί Κανάλι Ήχου",
    "Channel 0", "Κανάλι 0", "Channel 1", "Κανάλι 1", "Channel 2", "Κανάλι 2",
    "Channel 3", "Κανάλι 3", "Channel 4", "Κανάλι 4", "Channel 5", "Κανάλι 5",
    "Channel 6", "Κανάλι 6", "Channel 7", "Κανάλι 7", "Channel 8", "Κανάλι 8",
    "Channel 9", "Κανάλι 9", "Channel A", "Κανάλι A", "Channel B", "Κανάλι B",
    "Channel C", "Κανάλι C", "Channel D", "Κανάλι D", "Channel E", "Κανάλι E",
    "Channel F", "Κανάλι F", "Channel 1 (Square)", "Κανάλι 1 (Τετραγωνικό)",
    "Channel 2 (Square)", "Κανάλι 2 (Τετραγωνικό)", "Channel 3 (Wave)",
    "Κανάλι 3 (Κυματικό)", "Channel 4 (Noise)", "Κανάλι 4 (Θόρυβος)",
    "Channel A (FIFO)", "Κανάλι A (FIFO)", "Channel B (FIFO)",
    "Κανάλι B (FIFO)", "Audio Ring (Samples Available: %d)",
    "Ηχητικό Ring (Διαθέσιμα Δείγματα: %d)",
    "Audio Watchdog Triggered %d Times",
    "Ηχητικό Χρονόμετρο Φύλακα Πυροδοτήθηκε %d Φορές",
    ICON_FK_INFO_CIRCLE " Build Info", ICON_FK_INFO_CIRCLE " Πληροφορίες Build",
    "Commit Hash:", "Άρθροισμα Ελέγχου Commit:", ICON_FK_SERVER " Registers",
    ICON_FK_SERVER " Καταχωρητές", ICON_FK_LIST_OL " Disassembly",
    ICON_FK_LIST_OL " Αποσυναρμολόγηση Κώδικα",
    ICON_FK_EXCHANGE " Read/Write Memory Address",
    ICON_FK_EXCHANGE " Διεύθυνση Μνήμης Ανάγνωσης/Εγγραφής", "address",
    "διεύθυνση", "data (32 bit)", "δεδομένα (32 δυαδικά ψηφία)",
    "data (16 bit)", "δεδομένα (16 δυαδικά ψηφία)", "data (8 bit)",
    "δεδομένα (8 δυαδικά ψηφία)", "data (signed 32b)",
    "δεδομένα (32 δυαδικά ψηφία με πρόσημο)", "data (signed 16b)",
    "δεδομένα (16 δυαδικά ψηφία με πρόσημο)", "data (signed 8b)",
    "δεδομένα (8 δυαδικά ψηφία με πρόσημο)", ICON_FK_PENCIL_SQUARE_O " Memory",
    ICON_FK_PENCIL_SQUARE_O " Μνήμη", ICON_FK_AREA_CHART " Emulator Stats",
    ICON_FK_AREA_CHART " Καταστάσεις Εξομειωτή", "Show/Hide %s Panel\n",
    "Εμφάνιση/Απόκρυψη %s Πίνακα\n", "Press new button " ICON_FK_SIGN_IN,
    "Πατήστε το νέο κουμπί " ICON_FK_SIGN_IN, "Move Axis ",
    "Άξονας Μετακίνησης ", "Not bound", "Δεν έχει οριστεί", "Hat %d %s",
    "Hat %d %s", "Analog %d %s", "Αναλογικό %d %s", "Key %d", "Πλήκρο %d",
    "Analog %d (%0.2f)", "Αναλογικό %d (%0.2f)",
    "Load ROM from file (.gb, .gbc, .gba, .zip)",
    "Φόρτωση ROM από αρχείο (.gb, .gbc, .gba, .zip)",
    "You can also drag & drop a ROM to load it",
    "Μπορείς επίσης να σύρεις ένα ROM για να το φορτώσεις",
    "Load ROM(.gb, .gbc, .gba, .zip), save(.sav), or GBA bios (gba_bios.bin) "
    "from file",
    "Φόρτωση ROM (.gb, .gbc, .gba, .zip), αρχείο αποθήκευσης (.sav), ή «GBA "
    "bios» (gba_bios.bin)",
    "You can also drag & drop a ROM/save file to load it",
    "Μπορείς επίσης να σύρεις ένα ROM/αρχείο αποθήκευσης για να το φορτώσεις",
    "Open ROM", "Άνοιγμα ROM", ICON_FK_CLOCK_O " Load Recently Played Game",
    ICON_FK_CLOCK_O " Φόρτωση Πρόσφατα Παιγμένου Παιχνιδιού",
    ICON_FK_DOWNLOAD " Export Save", ICON_FK_DOWNLOAD " Εξαγωγή Αποθήκευσης",
    "No recently played games", "Δεν υπάρχουν πρόσφατα παιγμένα παιχνίδια",
    ICON_FK_GAMEPAD " Controllers", ICON_FK_GAMEPAD " Χειριστήρια",
    "Controller", "Χειριστήριο", "No Controller", "Χωρίς Χειριστήριο",
    "Reset Default Controller Bindings",
    "Επαναφορά Στα Προεπιλεγμένα Πλήκτρα Χειριστηρίου", "Rumble Supported",
    "Υποστήριξη Δόνησης", "Rumble Not Supported", "Δεν Υποστηρίζεται η Δόνηση",
    ICON_FK_FLOPPY_O " Save States",
    ICON_FK_FLOPPY_O " Αποθηκευτικές Καταστάσεις", "Save Slot %d", "Αποθήκ. %d",
    "Capture", "Αποθήκ.", "Restore", "Επαναφ.",
    "This save state came from an incompatible build. SkyEmu has attempted to "
    "recover it, but there may be issues",
    "Αυτή η αποθηκευτική κατάσταση προέρχεται από μια μη συμβατή έκδοση. Το "
    "SkyEmu έχει προσπαθήσει να την ανακτήσει, αλλά μπορεί να υπάρχουν "
    "προβλήματα",
    ICON_FK_DESKTOP " Display Settings", ICON_FK_DESKTOP " Ρυθμίσεις Οθόνης",
    "Screen Shader", "Shader Οθόνης",
    "Pixelate\0Bilinear\0LCD\0LCD & Subpixels\0Smooth Upscale (xBRZ)\0",
    "Πιξέλιασμα\0Διγραμμικό\0LCD\0LCD & Υποπίξελ\0Ομαλό Upscale (xBRZ)\0",
    "Screen Rotation", "Περιστροφή Οθόνης",
    "0 degrees\00090 degrees\000180 degrees\000270 degrees\0",
    "0 μοίρες\00090 μοίρες\000180 μοίρες\000270 μοίρες\0", "Color Correction",
    "Διόρθωση Χρώματος", "Strength: %.2f", "Δύναμη: %.2f", "Screen Ghosting",
    "Ghosting Οθόνης", "Force Integer Scaling",
    "Εξαναγκασμός Ακέραιας Κλιμάκωσης", "Stretch Screen to Fit",
    "Επέκταση Οθόνης για να Χωράει", "Game Boy Color Palette",
    "Παλέτα Game Boy Color", "GB Palette %d", "Παλέτα GB %d",
    "Reset Palette to Defaults", "Επαναφορά Παλέτας στις Προεπιλογές",
    ICON_FK_KEYBOARD_O " Keybinds", ICON_FK_KEYBOARD_O " Πλήκτρα",
    "Reset Default Keybinds", "Επαναφορά Προεπιλεγμένων Πλήκτρων",
    ICON_FK_WRENCH " Advanced", ICON_FK_WRENCH " Για Προχωρημένους",
    "Light Mode", "Φωτεινή Λειτουργία", "Show Debug Tools",
    "Εμφάνιση Εργαλείων Αποσφαλμάτωσης", "Adjust volume", "Ρύθμιση Έντασης",
    "Show/Hide Menu Panel", "Εμφάνιση/Απόκρυψη Πίνακα Μενού",
    "Rewind at 8x speed", "Επαναφορά Χρόνου σε 8x Ταχύτητα",
    "Rewind at 4x speed", "Επαναφορά Χρόνου σε 4x Ταχύτητα",
    "Toggle pause/play.\n When paused, the rom selection screen will be shown.",
    "Εναλλαγή παύσης/αναπαραγωγής.\n Όταν είναι σε παύση, θα εμφανιστεί η "
    "οθόνη επιλογής rom.",
    "Run at 2x Speed", "Τρέξε σε 2x Ταχύτητα",
    "Run at the fastest speed possible", "Τρέξε στην πιο γρήγορη ταχύτητα",
    "Screen", "Οθόνη", "LCD Shader Init", "Εκκινητής LCD Shader", "Menu",
    "Μενού", "Copy as..", "Αντιγραφή ως..", "Current", "Τρέχων", "Original",
    "Αρχικό", "Opacity", "Διαφάνεια",
    ICON_FK_HAND_O_RIGHT " Touch Control Settings",
    ICON_FK_HAND_O_RIGHT " Ρυθμίσεις Ελέγχου Αφής", "Hide when inactive",
    "Απόκρυψη όταν είναι ανενεργό", ICON_FK_FILE_O " Dump Memory to File",
    ICON_FK_FILE_O " Αποθήκευση Μνήμης σε Αρχείο", "Start Address",
    "Διεύθυνση Έναρξης", "Size", "Μέγεθος", "Save Memory Dump",
    "Αποθήκευση Αντίγραφου Μνήμης", ICON_FK_RANDOM " Last Branch Locations",
    ICON_FK_RANDOM " Τοποθεσίες Τελευταίας Διακλάδωσης", "Opacity: %.2f",
    "Διαφάνεια: %.2f", "Step Instruction", "Προχωρήσε Εντολή", "Step Frame",
    "Προχωρήσε Καρέ", "Disconnect Log", "Καταγραφή Αποσύνδεσης",
    ICON_FK_FOLDER_OPEN " Open File From Disk",
    ICON_FK_FOLDER_OPEN " Άνοιγμα Αρχείου Από Δίσκο", "Exit File Browser",
    "Κλείσιμο Περιηγητή Αρχείων", "Go back to recently loaded games",
    "Πήγαινε πίσω στα παιχνίδια που έχουν φορτωθεί πρόσφατα",
    "Go to parent directory", "Πήγαινε στον γονικό φάκελο", "UP", "Πάνω",
    "DOWN", "Κάτω", "LEFT", "Αριστερά", "RIGHT", "Δεξιά", "Reset Game",
    "Επανεκκίνηση", "Turbo A", "Τούρμπο A", "Turbo B", "Τούρμπο B", "Turbo X",
    "Τούρμπο X", "Turbo Y", "Τούρμπο Y", "Turbo L", "Τούρμπο L", "Turbo R",
    "Τούρμπο R", "Solar Sensor+", "Ηλιακός Αισθ. +", "Solar Sensor-",
    "Ηλιακός Αισθ. -", "Theme", "Εμφάνιση", "Solar Sensor",
    "Ηλιακός Αισθητήρας", "Brightness: %.2f", "Φωτεινότητα %.2f",
    "Dark\0Light\0Black\0", "Σκοτεινό\0Φωτεινό\0Μαύρο\0",
    "Always Show Menu/Nav Bar", "Πάντα Εμφάνιση Μενού/Μπάρας Πλοήγησης",
    "Language", "Γλώσσα", "SPACE", "Διάστημα", "ESCAPE", "ESC", "ENTER",
    "ENTER", "BACKSPACE", "BACKSPACE", "INSERT", "INSERT", "DELETE", "DELETE",
    "RIGHT", "Δεξιά", "LEFT", "Αριστερά", "DOWN", "Κάτω", "UP", "Πάνω",
    "LEFT_SHIFT", "Αριστερό Shift", "LEFT_CONTROL", "Αριστερό Control",
    "LEFT_ALT", "Αριστερό Alt", "LEFT_SUPER", "Αριστερό Super", "RIGHT_SHIFT",
    "Δεξί Shift", "RIGHT_CONTROL", "Δεξί Control", "RIGHT_ALT", "Δεξί Alt",
    "RIGHT_SUPER", "Δεξί Super", "MENU", "Μενού",
    "Enable Turbo and Hold Button Modifiers",
    "Ενεργ. Τροποπ. Τούρμπο και Πατημένου Κουμπιού", "Scale", "Κλίμακα",
    "Scale: %.2f", "Κλίμακα: %.2f", "GBA Color Correction Type",
    "Τύπος Διόρθ. Χρώματος GBA", ICON_FK_TEXT_HEIGHT " GUI",
    ICON_FK_TEXT_HEIGHT " Γραφικό Περιβάλλον Διεπαφής Χρήστη", "Full Screen",
    "Πλήρης Οθόνη", ICON_FK_CODE_FORK " Additional Search Paths",
    ICON_FK_CODE_FORK " Επιπλέον Μονοπάτια Αναζήτησης", "Save File/State Path",
    "Μονοπ. Αποθηκ. Καταστ.", "BIOS/Firmware Path", "Μονοπ. BIOS/Υλικολογ.",
    "Create new save files in Save Path",
    "Δημιουργία νέων αρχείων στο Μονοπάτι Αποθήκευσης",
    ICON_FK_CROSSHAIRS " Located BIOS/Firmware Files",
    ICON_FK_CROSSHAIRS " Βρέθεντα BIOS/Υλικολογισμικά αρχεία",
    "Force GB games to run in DMG mode",
    "Αναγκαστική εκκίν. GB παιχνιδιών σε DMG λειτουργία",
    "Enable HTTP Control Server", "Ενεργοποίηση HTTP Σέρβερ Ελέγχου",
    "Server Port", "Θύρα Σέρβερ", "Toggle Full Screen", "Εναλλ. Πλήρους Οθ.",
    "Can't find all needed BIOS/Boot ROM/Firmware Files.",
    "Δεν βρέθηκαν όλα τα απαραίτητα BIOS/Boot ROM/Υλικολογισμικά αρχεία.",
    "Accuracy will suffer and some features won't work.",
    "Η ακρίβεια θα επηρεαστεί και ορισμένες λειτουργίες δεν θα λειτουργήσουν.",
    // New in v3
    "Avoid NDS Touchscreen", "Αποφυγή οθ. αφής NDS", ICON_FK_PLUS " New",
    ICON_FK_PLUS " Νέο", ICON_FK_KEY " Action Replay Codes",
    ICON_FK_KEY " Action Replay", "Create new files in paths",
    "Δημιουργία νέων αρχείων στα μονοπάτια", "Cheat Code Path",
    "Μονοπάτι Cheat Code", NULL, NULL};

// Dutch translation by https://github.com/DenSinH
static char *nl_localization_array[] = {
    ICON_FK_FILE_O " Load Game", ICON_FK_FILE_O " Spel laden", "Up", "Omhoog",
    "Down", "Omlaag", "Left", "Links", "Right", "Rechts", "Start", "Start",
    "Select", "Select", "Fold Screen (NDS)", "Scherm dichtvouwen (NDS)",
    "Tap Screen (NDS)", "Scherm aanraken (NDS)",
    "Emulator " ICON_FK_PAUSE "/" ICON_FK_PLAY,
    "Emulator " ICON_FK_PAUSE "/" ICON_FK_PLAY, "Emulator " ICON_FK_BACKWARD,
    "Emulator " ICON_FK_BACKWARD, "Emulator " ICON_FK_FORWARD,
    "Emulator " ICON_FK_FORWARD, "Emulator " ICON_FK_FAST_FORWARD,
    "Emulator " ICON_FK_FAST_FORWARD, "Capture State 0", "Staat 0 vastleggen",
    "Restore State 0", "Staat 0 herstellen", "Capture State 1",
    "Staat 1 vastleggen", "Restore State 1", "Staat 1 herstellen",
    "Capture State 2", "Staat 2 vastleggen", "Restore State 2",
    "Staat 2 herstellen", "Capture State 3", "Staat 3 vastleggen",
    "Restore State 3", "Staat 3 herstellen", "Analog Up/Down",
    "Analoog omhoog/omlaag", "Analog Left/Right", "Analoog links/rechts",
    "Analog L", "Analoog L", "Analog R", "Analoog R", "Display FPS: %2.1f\n",
    "Scherm FPS: %2.1f\n", "Emulation FPS: %2.1f\n", "Emulatie FPS: %2.1f\n",
    ICON_FK_VOLUME_UP " Audio", ICON_FK_VOLUME_UP " Audio",
    "Left Audio Channel", "Linker Audiokanaal", "Right Audio Channel",
    "Rechter Audiokanaal", "Channel 0", "Kanaal 0", "Channel 1", "Kanaal 1",
    "Channel 2", "Kanaal 2", "Channel 3", "Kanaal 3", "Channel 4", "Kanaal 4",
    "Channel 5", "Kanaal 5", "Channel 6", "Kanaal 6", "Channel 7", "Kanaal 7",
    "Channel 8", "Kanaal 8", "Channel 9", "Kanaal 9", "Channel A", "Kanaal A",
    "Channel B", "Kanaal B", "Channel C", "Kanaal C", "Channel D", "Kanaal D",
    "Channel E", "Kanaal E", "Channel F", "Kanaal F", "Channel 1 (Square)",
    "Kanaal 1 (Vierkant)", "Channel 2 (Square)", "Kanaal 2 (Vierkant)",
    "Channel 3 (Wave)", "Kanaal 3 (Golf)", "Channel 4 (Noise)",
    "Kanaal 4 (Ruis)", "Channel A (FIFO)", "Kanaal A (FIFO)",
    "Channel B (FIFO)", "Kanaal B (FIFO)", "Audio Ring (Samples Available: %d)",
    "Audio Ring (Monsters Beschikbaar %d)", "Audio Watchdog Triggered %d Times",
    "Audio Watchdog %d Keer Geactiveerd", ICON_FK_INFO_CIRCLE " Build Info",
    ICON_FK_INFO_CIRCLE " Versieinformatie",
    "Commit Hash:", "Commit Hash:", ICON_FK_SERVER " Registers",
    ICON_FK_SERVER " Registers", ICON_FK_LIST_OL " Disassembly",
    ICON_FK_LIST_OL " Disassembly",
    ICON_FK_EXCHANGE " Read/Write Memory Address",
    ICON_FK_EXCHANGE " Lees/Schrijf Geheugenadres", "address", "adres",
    "data (32 bit)", "data (32 bit)", "data (16 bit)", "data (16 bit)",
    "data (8 bit)", "data (8 bit)", "data (signed 32b)",
    "data (32 bit met teken)", "data (signed 16b)", "data (16 bit met teken)",
    "data (signed 8b)", "data (8 bit met teken)",
    ICON_FK_PENCIL_SQUARE_O " Memory", ICON_FK_PENCIL_SQUARE_O " Geheugen",
    ICON_FK_AREA_CHART " Emulator Stats",
    ICON_FK_AREA_CHART " Emulator Gegevens", "Show/Hide %s Panel\n",
    "Toon/Verberg %s Paneel\n", "Press new button " ICON_FK_SIGN_IN,
    " Klik op de nieuwe knop" ICON_FK_SIGN_IN, "Move Axis ", "Bewegingsas",
    "Not bound", "Niet ingesteld", "Hat %d %s", "Hat %d %s", "Analog %d %s",
    "Analoog %d %s", "Key %d", "Toets %d", "Analog %d (%0.2f)",
    "Analoog %d (%0.2f)", "Load ROM from file (.gb, .gbc, .gba, .zip)",
    "Laad ROM uit bestand (.gb, .gbc, .gba, .zip)",
    "You can also drag & drop a ROM to load it",
    "Je kan ook een bestand slepen en neerzetten om het te laden",
    "Load ROM(.gb, .gbc, .gba, .zip), save(.sav), or GBA bios (gba_bios.bin) "
    "from file",
    "Laad ROM (.gb, .gbc, .gba, .zip), save (.sav) of GBA BIOS (gba_bios.bin)",
    "You can also drag & drop a ROM/save file to load it",
    "Je kan ook een ROM- of savebestand slepen en neerzetten om het te laden",
    "Open ROM", "ROM Openen", ICON_FK_CLOCK_O " Load Recently Played Game",
    ICON_FK_CLOCK_O " Laad Recent Gespeeld Spel",
    ICON_FK_DOWNLOAD " Export Save", ICON_FK_DOWNLOAD " Save Exporteren",
    "No recently played games", "Geen recent gespeelde spellen",
    ICON_FK_GAMEPAD " Controllers", ICON_FK_GAMEPAD " Controllers",
    "Controller", "Controller", "No Controller", "Geen Controller",
    "Reset Default Controller Bindings",
    "Standaard Controllerinstellingen Herstellen", "Rumble Supported",
    "Vibratie Ondersteund", "Rumble Not Supported", "Vibratie Niet Ondersteund",
    ICON_FK_FLOPPY_O " Save States", ICON_FK_FLOPPY_O " Staten Opslaan",
    "Save Slot %d", "Save Slot %d", "Capture", "Vastleggen", "Restore",
    "Herstellen",
    "This save state came from an incompatible build. SkyEmu has attempted to "
    "recover it, but there may be issues",
    "Deze save staat komt van een oude versie. SkyEmu heeft geprobeerd hem te "
    "herstellen, maar er kunnen problemen zijn",
    ICON_FK_DESKTOP " Display Settings",
    ICON_FK_DESKTOP " Weergave Instellingen", "Screen Shader", "Scherm Shader",
    "Pixelate\0Bilinear\0LCD\0LCD & Subpixels\0Smooth Upscale (xBRZ)\0",
    "Pixeleren\0Bilineair\0LCD\0LCD & Subpixels\0Gladde Opschaling (xBRZ)\0",
    "Screen Rotation", "Scherm Rotatie",
    "0 degrees\00090 degrees\000180 degrees\000270 degrees\0",
    "0 graden\00090 graden\000180 graden\000270 graden\0", "Color Correction",
    "Kleurcorrectie", "Strength: %.2f", "Sterkte %.2f", "Screen Ghosting",
    "Scherm Ghosting", "Force Integer Scaling", "Forceer Gehele Schaling",
    "Stretch Screen to Fit", "Scherm Uitrekken", "Game Boy Color Palette",
    "Game Boy Color Palet", "GB Palette %d", "GB Palet %d",
    "Reset Palette to Defaults", "Paletten Naar Standaard Herstellen",
    ICON_FK_KEYBOARD_O " Keybinds", ICON_FK_KEYBOARD_O " Sneltoetsen",
    "Reset Default Keybinds", "Standaard Sneltoetsen Herstellen",
    ICON_FK_WRENCH " Advanced", ICON_FK_WRENCH " Geavanceerd", "Light Mode",
    "Lichte Modus", "Show Debug Tools", "Debug Hulpprogrammas Weergeven",
    "Adjust volume", "Volume Aanpassen", "Show/Hide Menu Panel",
    "Menu Tonen/Verbergen", "Rewind at 8x speed",
    "Terugspoelen met 8x snelheid", "Rewind at 4x speed",
    "Terugspoelen met 4x snelheid",
    "Toggle pause/play.\n When paused, the rom selection screen will be shown.",
    "Pauzeren/Afspelen. Wanneer gepauzeerd wordt het ROM selectiemenu getoond",
    "Run at 2x Speed", "Op 2x snelheid afspelen",
    "Run at the fastest speed possible", "Op maximale snelheid afspelen",
    "Screen", "Scherm", "LCD Shader Init", "LCD Shader Instellen", "Menu",
    "Menu", "Copy as..", "Kopiëren als...", "Current", "Huidig", "Original",
    "Origineel", "Opacity", "Ondoorzichtigheid",
    ICON_FK_HAND_O_RIGHT " Touch Control Settings",
    ICON_FK_HAND_O_RIGHT " Aanraak instellingen", "Hide when inactive",
    "Verbergen bij inactiviteit", ICON_FK_FILE_O " Dump Memory to File",
    ICON_FK_FILE_O " Geheugen Naar Bestand Schrijven", "Start Address",
    "Start Adres", "Size", "Grootte", "Save Memory Dump",
    "Geheugendump Opslaan", ICON_FK_RANDOM " Last Branch Locations",
    ICON_FK_RANDOM " Laatste Branchlocaties", "Opacity: %.2f",
    "Ondoorzichtigheid %.2f", "Step Instruction", "Instructie Stappen",
    "Step Frame", "Frame Stappen", "Disconnect Log", "Log Ontkoppelen",
    ICON_FK_FOLDER_OPEN " Open File From Disk",
    ICON_FK_FOLDER_OPEN " Bestand Van Schijf Openen", "Exit File Browser",
    "Bestandsverkenner Sluiten", "Go back to recently loaded games",
    "Ga terug naar recent geladen spellen", "Go to parent directory",
    "Naar bovenliggende map", "UP", "OMHOOG", "DOWN", "OMLAAG", "LEFT", "LINKS",
    "RIGHT", "RECHTS", "Reset Game", "Spel terugzetten", "Turbo A", "Turbo A",
    "Turbo B", "Turbo B", "Turbo X", "Turbo X", "Turbo Y", "Turbo Y", "Turbo L",
    "Turbo L", "Turbo R", "Turbo R", "Solar Sensor+", "Zonnesensor +",
    "Solar Sensor-", "Zonnesensor -", "Theme", "Thema", "Solar Sensor",
    "Zonnesensor", "Brightness: %.2f", "Helderheid %.2f",
    "Dark\0Light\0Black\0", "Donker\0Licht\0Zwart\0",
    "Always Show Menu/Nav Bar", "Menu/Navigatiebalk Altijd Tonen", "Language",
    "Taal", "SPACE", "SPATIE", "ESCAPE", "ESC", "ENTER", "ENTER", "BACKSPACE",
    "BACKSPACE", "INSERT", "INSERT", "DELETE", "DELETE", "RIGHT", "RECHTS",
    "LEFT", "LINKS", "DOWN", "OMLAAG", "UP", "OMHOOG", "LEFT_SHIFT",
    "LINKER_SHIFT", "LEFT_CONTROL", "LINKER_CONTROL", "LEFT_ALT", "LINKER_ALT",
    "LEFT_SUPER", "LINKER_SUPER", "RIGHT_SHIFT", "RECHTER_SHIFT",
    "RIGHT_CONTROL", "RECHTER_CONTROL", "RIGHT_ALT", "RECHTER_ALT",
    "RIGHT_SUPER", "RECHTER_SUPER", "MENU", "MENU",
    "Enable Turbo and Hold Button Modifiers",
    "Turbo- en Indrukkingsaanpassingen Inschakelen", "Scale", "Schaal",
    "Scale: %.2f", "Schaal %.2f", "GBA Color Correction Type",
    "GBA Kleurcorrectie Type", ICON_FK_TEXT_HEIGHT " GUI",
    ICON_FK_TEXT_HEIGHT " GUI", "Full Screen", "Volledig Scherm",
    ICON_FK_CODE_FORK " Additional Search Paths",
    ICON_FK_CODE_FORK " Extra Zoekpaden", "Save File/State Path",
    "Save Bestand/Staat Pad", "BIOS/Firmware Path", "BIOS/Firmware Pad",
    "Create new save files in Save Path",
    "Nieuwe savebestanden in Save Pad maken",
    ICON_FK_CROSSHAIRS " Located BIOS/Firmware Files",
    ICON_FK_CROSSHAIRS " BIOS/Firmwarebestanden Gevonden",
    "Force GB games to run in DMG mode",
    "Forceer GB spellen in DMG modus te runnen", "Enable HTTP Control Server",
    "HTTP Controleserver Inschakelen", "Server Port", "Server Port",
    "Toggle Full Screen", "Volledig Scherm In- of Uitschakelen",
    "Can't find all needed BIOS/Boot ROM/Firmware Files.",
    "Kan niet alle benodigde BIOS/Boot ROM/Firmwarebestanden vinden",
    "Accuracy will suffer and some features won't work.",
    "Precisie zal minder worden en sommige functies zullen niet werken",
    // New in v3
    "Avoid NDS Touchscreen", "Vermijd NDS Aanraakscherm", ICON_FK_PLUS " New",
    ICON_FK_PLUS "  Nieuw", ICON_FK_KEY " Action Replay Codes",
    ICON_FK_KEY " Action Replay Codes", "Create new files in paths",
    "Maak nieuwe bestanden in paden", "Cheat Code Path", "Cheat Code Pad", NULL,
    NULL};
// Danish Translation by https://github.com/nadiaholmquist
static char *da_localization_array[] = {
    ICON_FK_FILE_O " Load Game", ICON_FK_FILE_O " Åbn spil", "Up", "Op", "Down",
    "Ned", "Left", "Venstre", "Right", "Højre", "Start", "Start", "Select",
    "Select", "Fold Screen (NDS)", "Fold skærm (NDS)", "Tap Screen (NDS)",
    "Rør skærm (NDS)", "Emulator " ICON_FK_PAUSE "/" ICON_FK_PLAY,
    "Emulator " ICON_FK_PAUSE "/" ICON_FK_PLAY, "Emulator " ICON_FK_BACKWARD,
    "Emulator " ICON_FK_BACKWARD, "Emulator " ICON_FK_FORWARD,
    "Emulator " ICON_FK_FORWARD, "Emulator " ICON_FK_FAST_FORWARD,
    "Emulator " ICON_FK_FAST_FORWARD, "Capture State 0", "Gem snapshot 0",
    "Restore State 0", "Gendan snapshot 0", "Capture State 1", "Gem snapshot 1",
    "Restore State 1", "Gendan snapshot 1", "Capture State 2", "Gem snapshot 2",
    "Restore State 2", "Gendan snapshot 2", "Capture State 3", "Gem snapshot 3",
    "Restore State 3", "Gendan snapshot 3", "Analog Up/Down", "Analog op/ned",
    "Analog Left/Right", "Analog venstre/højre", "Analog L", "Analog L",
    "Analog R", "Analog R", "Display FPS: %2.1f\n", "Skærmens FPS: %2.1f\n",
    "Emulation FPS: %2.1f\n", "Emulatorens FPS: %2.1f\n",
    ICON_FK_VOLUME_UP " Audio", ICON_FK_VOLUME_UP " Lyd", "Left Audio Channel",
    "Venstre lydkanal", "Right Audio Channel", "Højre lydkanal", "Channel 0",
    "Kanal 0", "Channel 1", "Kanal 1", "Channel 2", "Kanal 2", "Channel 3",
    "Kanal 3", "Channel 4", "Kanal 4", "Channel 5", "Kanal 5", "Channel 6",
    "Kanal 6", "Channel 7", "Kanal 7", "Channel 8", "Kanal 8", "Channel 9",
    "Kanal 9", "Channel A", "Kanal A", "Channel B", "Kanal B", "Channel C",
    "Kanal C", "Channel D", "Kanal D", "Channel E", "Kanal E", "Channel F",
    "Kanal F", "Channel 1 (Square)", "Kanal 1 (Firkant)", "Channel 2 (Square)",
    "Kanal 2 (Firkant)", "Channel 3 (Wave)", "Kanal 3 (Wave)",
    "Channel 4 (Noise)", "Kanal 4 (Støj)", "Channel A (FIFO)", "Kanal A (FIFO)",
    "Channel B (FIFO)", "Kanal B (FIFO)", "Audio Ring (Samples Available: %d)",
    "Lyd-ring (samples tilgængelige: %d)", "Audio Watchdog Triggered %d Times",
    "Lyd-watchdog udløst %d gange", ICON_FK_INFO_CIRCLE " Build Info",
    ICON_FK_INFO_CIRCLE " Build-info",
    "Commit Hash:", "Commit-hash:", ICON_FK_SERVER " Registers",
    ICON_FK_SERVER " Registre", ICON_FK_LIST_OL " Disassembly",
    ICON_FK_LIST_OL " Disassembly",
    ICON_FK_EXCHANGE " Read/Write Memory Address",
    ICON_FK_EXCHANGE " Læs/skriv hukommelsesadresse", "address", "adresse",
    "data (32 bit)", "data (32-bit)", "data (16 bit)", "data (16-bit)",
    "data (8 bit)", "data (8-bit)", "data (signed 32b)", "data (signeret 32b)",
    "data (signed 16b)", "data (signeret 16b)", "data (signed 8b)",
    "data (signeret 8b)", ICON_FK_PENCIL_SQUARE_O " Memory",
    ICON_FK_PENCIL_SQUARE_O " Hukommelse", ICON_FK_AREA_CHART " Emulator Stats",
    ICON_FK_AREA_CHART " Emulator-statistik", "Show/Hide %s Panel\n",
    "Vis/skjul %s-panel\n", "Press new button " ICON_FK_SIGN_IN,
    "Tryk på ny knap " ICON_FK_SIGN_IN, "Move Axis ", "Flyt akse ", "Not bound",
    "Ikke bundet", "Hat %d %s", "Hat %d %s", "Analog %d %s", "Analog %d %s",
    "Key %d", "Knap %d", "Analog %d (%0.2f)", "Analog %d (%0.2f)",
    "Load ROM from file (.gb, .gbc, .gba, .zip)",
    "Åbn ROM fra fil (.gb, .gbc, .gba, .zip)",
    "You can also drag & drop a ROM to load it",
    "Du kan også trække og slippe et ROM for at åbne det",
    "Load ROM(.gb, .gbc, .gba, .zip), save(.sav), or GBA bios (gba_bios.bin) "
    "from file",
    "Åbn ROM(.gb, .gbc, .gba, .zip), gemt spil(.sav), eller GBA-bios "
    "(gba_bios.bin) fra fil",
    "You can also drag & drop a ROM/save file to load it",
    "Du kan også trække og slippe et ROM eller gemt spil for at åbne det",
    "Open ROM", "Åbn ROM", ICON_FK_CLOCK_O " Load Recently Played Game",
    ICON_FK_CLOCK_O " Åbn nyligt spillet spil", ICON_FK_DOWNLOAD " Export Save",
    ICON_FK_DOWNLOAD " Eksporter gemt spil", "No recently played games",
    "Ingen nyligt spillede spil", ICON_FK_GAMEPAD " Controllers",
    ICON_FK_GAMEPAD " Controllere", "Controller", "Controller", "No Controller",
    "Ingen controller", "Reset Default Controller Bindings",
    "Nulstil til standard-controllerknapper", "Rumble Supported",
    "Vibration understøttet", "Rumble Not Supported",
    "Vibration ikke understøttet", ICON_FK_FLOPPY_O " Save States",
    ICON_FK_FLOPPY_O " Snapshots", "Save Slot %d", "Snapshot %d", "Capture",
    "Gem", "Restore", "Gendan",
    "This save state came from an incompatible build. SkyEmu has attempted to "
    "recover it, but there may be issues",
    "Dette snapshot kom fra en ikke-kompatibel build. SkyEmu har forsøgt at "
    "gendanne det, men der kan opstå fejl",
    ICON_FK_DESKTOP " Display Settings", ICON_FK_DESKTOP " Skærmindstillinger",
    "Screen Shader", "Skærm-shader",
    "Pixelate\0Bilinear\0LCD\0LCD & Subpixels\0Smooth Upscale (xBRZ)\0",
    "Pixeler\0Bilineær\0LCD\0LCD & subpixels\0Jævn opskalering (xBRZ)\0",
    "Screen Rotation", "Skærmrotation",
    "0 degrees\00090 degrees\000180 degrees\000270 degrees\0",
    "0 grader\00090 grader\000180 grader\000270 grader\0", "Color Correction",
    "Farvekorrektur", "Strength: %.2f", "Styrke: %.2f", "Screen Ghosting",
    "Skærm-ghosting", "Force Integer Scaling", "Tving heltalsskalering",
    "Stretch Screen to Fit", "Stræk skærmen til at udfylde",
    "Game Boy Color Palette", "Game Boy Color-palet", "GB Palette %d",
    "GB-palet %d", "Reset Palette to Defaults", "Nulstil palet til standard",
    ICON_FK_KEYBOARD_O " Keybinds", ICON_FK_KEYBOARD_O " Tastaturbindinger",
    "Reset Default Keybinds", "Nulstil til standard-tastaturbindinger",
    ICON_FK_WRENCH " Advanced", ICON_FK_WRENCH " Avanceret", "Light Mode",
    "Lys tilstand", "Show Debug Tools", "Vis værktøjer til fejlfinding",
    "Adjust volume", "Juster lydstyrke", "Show/Hide Menu Panel",
    "Vis/skjul menupanel", "Rewind at 8x speed",
    "Spol tilbage med 8x hastighed", "Rewind at 4x speed",
    "Spol tilbage med 4x hastighed",
    "Toggle pause/play.\n When paused, the rom selection screen will be shown.",
    "Skift mellem pause/afspilning.\n Når på pause vises skærmen til valg af "
    "ROM.",
    "Run at 2x Speed", "Kør med 2x hastighed",
    "Run at the fastest speed possible", "Kør med højest mulige hastighed",
    "Screen", "Skærm", "LCD Shader Init", "LCD-shader-initialisering", "Menu",
    "Menu", "Copy as..", "Kopier som..", "Current", "Nuværende", "Original",
    "Original", "Opacity", "Uigennemsigtighed",
    ICON_FK_HAND_O_RIGHT " Touch Control Settings",
    ICON_FK_HAND_O_RIGHT "Indstillinger for berøringsstyring",
    "Hide when inactive", "Skjul når inaktiv",
    ICON_FK_FILE_O " Dump Memory to File",
    ICON_FK_FILE_O " Dump hukommelse til fil", "Start Address", "Startadresse",
    "Size", "Størrelse", "Save Memory Dump", "Gem hukommelses-dump",
    ICON_FK_RANDOM " Last Branch Locations",
    ICON_FK_RANDOM " Sidste branch-placeringer", "Opacity: %.2f",
    "Uigennemsigtighed: %.2f", "Step Instruction", "Kør én instruktion",
    "Disconnect Log", "Frakobl log", ICON_FK_FOLDER_OPEN " Open File From Disk",
    ICON_FK_FOLDER_OPEN " Åbn fil fra disk", "Exit File Browser",
    "Luk filbrowser", "Go back to recently loaded games",
    "Gå tilbage til nyligt spillede spil", "Go to parent directory",
    "Gå et mappeniveau op", "UP", "OP", "DOWN", "NED", "LEFT", "VENSTRE",
    "RIGHT", "HØJRE", "Reset Game", "Genstart spil", "Turbo A", "Turbo A",
    "Turbo B", "Turbo B", "Turbo X", "Turbo X", "Turbo Y", "Turbo Y", "Turbo L",
    "Turbo L", "Turbo R", "Turbo R", "Solar Sensor+", "Solsensor +",
    "Solar Sensor-", "Solsensor -", "Theme", "Tema", "Solar Sensor",
    "Solsensor", "Brightness: %.2f", "Lysstyrke: %.2f", "Dark\0Light\0Black\0",
    "Mørkt\0Lyst\0Sort\0", "Always Show Menu/Nav Bar",
    "Vis altid menu/navigeringslinje", "Language", "Sprog", "SPACE",
    "MELLEMRUM", "ESCAPE", "ESC", "ENTER", "ENTER", "BACKSPACE", "BACKSPACE",
    "INSERT", "INSERT", "DELETE", "DELETE", "RIGHT", "HØJRE", "LEFT", "VENSTRE",
    "DOWN", "NED", "UP", "OP", "LEFT_SHIFT", "Venstre Shift", "LEFT_CONTROL",
    "Venstre Control", "LEFT_ALT", "Venstre Alt", "LEFT_SUPER", "Venstre Super",
    "RIGHT_SHIFT", "Højre Shift", "RIGHT_CONTROL", "Højre Control", "RIGHT_ALT",
    "Højre Alt", "RIGHT_SUPER", "Højre Super", "MENU", "Menu",
    "Enable Turbo and Hold Button Modifiers",
    "Aktiver turbo og hold af knapper", "Scale", "Skalering", "Scale: %.2f",
    "Skalering: %.2f", "GBA Color Correction Type",
    "Farvekorrektur-type for GBA", ICON_FK_TEXT_HEIGHT " GUI",
    ICON_FK_TEXT_HEIGHT " Grænseflade", "Full Screen", "Fuld skærm",
    ICON_FK_CODE_FORK " Additional Search Paths",
    ICON_FK_CODE_FORK " Ekstra søgestier", "Save File/State Path",
    "Sti til gem/snapshots", "BIOS/Firmware Path", "Sti til BIOS/firmware",
    "Create new save files in Save Path",
    "Opret nye gemt spil-filer under gemte-stien",
    ICON_FK_CROSSHAIRS " Located BIOS/Firmware Files",
    ICON_FK_CROSSHAIRS " Fundne BIOS/firmware-filer",
    "Force GB games to run in DMG mode",
    "Gennemtving GB-spil at køre i DMG-tilstand", "Enable HTTP Control Server",
    "Aktiver HTTP-kontrolserver", "Server Port", "Serverport",
    "Toggle Full Screen", "Fuld skærm til/fra",
    "Can't find all needed BIOS/Boot ROM/Firmware Files.",
    "Kan ikke finde alle nødvendige BIOS-, boot ROM-\neller firmware-filer.",
    "Accuracy will suffer and some features won't work.",
    "Emulering vil være mindre akkurat og nogle funk-\ntioner vil ikke virke.",
    // New in V3
    "Avoid NDS Touchscreen", "Undgå NDS-touchskærm", ICON_FK_PLUS " New",
    ICON_FK_PLUS " Ny", ICON_FK_KEY " Action Replay Codes",
    ICON_FK_KEY " Action Replay-koder", "Create new files in paths",
    "Opret nye filer under stierne", "Cheat Code Path", "Snydekode-sti", NULL,
    NULL};
// German translation https://github.com/ladystarbreeze
static char *de_localization_array[] = {
    ICON_FK_FILE_O " Load Game", ICON_FK_FILE_O " Lade Spiel", "Up", "Hoch",
    "Down", "Runter", "Left", "Links", "Right", "Rechts", "Start", "Start",
    "Select", "Select", "Fold Screen (NDS)", "Bildschirm zuklappen (NDS)",
    "Tap Screen (NDS)", "Bildschirm berühren (NDS)",
    "Emulator " ICON_FK_PAUSE "/" ICON_FK_PLAY,
    "Emulator " ICON_FK_PAUSE "/" ICON_FK_PLAY, "Emulator " ICON_FK_BACKWARD,
    "Emulator " ICON_FK_BACKWARD, "Emulator " ICON_FK_FORWARD,
    "Emulator " ICON_FK_FORWARD, "Emulator " ICON_FK_FAST_FORWARD,
    "Emulator " ICON_FK_FAST_FORWARD, "Capture State 0", "Erstelle Save 0",
    "Restore State 0", "Lade Save 0", "Capture State 1", "Erstelle Save 1",
    "Restore State 1", "Lade Save 1", "Capture State 2", "Erstelle Save 2",
    "Restore State 2", "Lade Save 2", "Capture State 3", "Erstelle Save 3",
    "Restore State 3", "Lade Save 3", "Analog Up/Down", "Analog hoch/runter",
    "Analog Left/Right", "Analog links/rechts", "Analog L", "Analog L",
    "Analog R", "Analog R", "Display FPS: %2.1f\n", "Anzeige-FPS: %2.1f\n",
    "Emulation FPS: %2.1f\n", "Emulierte FPS: %2.1f\n",
    ICON_FK_VOLUME_UP " Audio", ICON_FK_VOLUME_UP " Audio",
    "Left Audio Channel", "Linker Audiokanal", "Right Audio Channel",
    "Rechter Audiokanal", "Channel 0", "Kanal 0", "Channel 1", "Kanal 1",
    "Channel 2", "Kanal 2", "Channel 3", "Kanal 3", "Channel 4", "Kanal 4",
    "Channel 5", "Kanal 5", "Channel 6", "Kanal 6", "Channel 7", "Kanal 7",
    "Channel 8", "Kanal 8", "Channel 9", "Kanal 9", "Channel A", "Kanal A",
    "Channel B", "Kanal B", "Channel C", "Kanal C", "Channel D", "Kanal D",
    "Channel E", "Kanal E", "Channel F", "Kanal F", "Channel 1 (Square)",
    "Kanal 1 (Rechteck)", "Channel 2 (Square)", "Kanal 2 (Rechteck)",
    "Channel 3 (Wave)", "Kanal 3 (Welle)", "Channel 4 (Noise)",
    "Kanal 4 (Rauschen)", "Channel A (FIFO)", "Kanal A (FIFO)",
    "Channel B (FIFO)", "Kanal B (FIFO)", "Audio Ring (Samples Available: %d)",
    "Audio-Ringpuffer (%d Samples verfügbar)",
    "Audio Watchdog Triggered %d Times", "Audio-Watchdog %d-mal ausgelöst",
    ICON_FK_INFO_CIRCLE " Build Info",
    ICON_FK_INFO_CIRCLE " Build-Informationen",
    "Commit Hash:", "Commit-Hash:", ICON_FK_SERVER " Registers",
    ICON_FK_SERVER " Register", ICON_FK_LIST_OL " Disassembly",
    ICON_FK_LIST_OL " Disassembly",
    ICON_FK_EXCHANGE " Read/Write Memory Address",
    ICON_FK_EXCHANGE " Lese-/Schreibadresse", "address", "Adresse",
    "data (32 bit)", "Daten (32-bit)", "data (16 bit)", "Daten (16-bit)",
    "data (8 bit)", "Daten (8-bit)", "data (signed 32b)", "Daten (32b signed)",
    "data (signed 16b)", "Daten (16b signed)", "data (signed 8b)",
    "Daten (8b signed)", ICON_FK_PENCIL_SQUARE_O " Memory",
    ICON_FK_PENCIL_SQUARE_O " Speicher", ICON_FK_AREA_CHART " Emulator Stats",
    ICON_FK_AREA_CHART " Statistiken", "Show/Hide %s Panel\n",
    "Zeige/Verstecke %s-Feld\n", "Press new button " ICON_FK_SIGN_IN,
    "Drücke neuen Knopf " ICON_FK_SIGN_IN, "Move Axis ", "Bewege Achse",
    "Not bound", "Ungebunden", "Hat %d %s", "Hat %d %s", "Analog %d %s",
    "Analog %d %s", "Key %d", "Taste %d", "Analog %d (%0.2f)",
    "Analog %d (%0.2f)", "Load ROM from file (.gb, .gbc, .gba, .zip)",
    "Lade ROM von Datei (.gb, .gbc, .gba, .zip)",
    "You can also drag & drop a ROM to load it",
    "Du kannst ein ROM auch durch Ziehen und Ablegen laden",
    "Load ROM(.gb, .gbc, .gba, .zip), save(.sav), or GBA bios (gba_bios.bin) "
    "from file",
    "Lade ROM (.gb, .gbc, .gba, .zip), Save (.sav) oder GBA-BIOS "
    "(gba_bios.bin)",
    "You can also drag & drop a ROM/save file to load it",
    "Du kannst ein ROM/Save auch durch Ziehen und Ablegen laden", "Open ROM",
    "Öffne ROM", ICON_FK_CLOCK_O " Load Recently Played Game",
    ICON_FK_CLOCK_O " Lade zuletzt gespieltes Spiel",
    ICON_FK_DOWNLOAD " Export Save", ICON_FK_DOWNLOAD " Exportiere Save",
    "No recently played games", "Keine zuletzt gespielten Spiele",
    ICON_FK_GAMEPAD " Controllers", ICON_FK_GAMEPAD " Controller", "Controller",
    "Controller", "No Controller", "Kein Controller",
    "Reset Default Controller Bindings", "Stelle Standardbelegungen wieder her",
    "Rumble Supported", "Rumble unterstützt", "Rumble Not Supported",
    "Rumble nicht unterstützt", ICON_FK_FLOPPY_O " Save States",
    ICON_FK_FLOPPY_O " Saves", "Save Slot %d", "Save %d", "Capture",
    "Erstellen", "Restore", "Laden",
    "This save state came from an incompatible build. SkyEmu has attempted to "
    "recover it, but there may be issues",
    "Dieses Save stammt von einer inkompatiblen Version. SkyEmu hat versucht, "
    "es wiederherzustellen, aber es können Probleme auftreten.",
    ICON_FK_DESKTOP " Display Settings",
    ICON_FK_DESKTOP " Bildschirmeinstellungen", "Screen Shader",
    "Bildschirm-Shader",
    "Pixelate\0Bilinear\0LCD\0LCD & Subpixels\0Smooth Upscale (xBRZ)\0",
    "Pixelieren\0Bilinear\0LCD\0LCD und Subpixel\0Weiche Hochskalierung "
    "(xBRZ)\0",
    "Screen Rotation", "Rotation",
    "0 degrees\00090 degrees\000180 degrees\000270 degrees\0",
    "0 Grad\00090 Grad\000180 Grad\000270 Grad\0", "Color Correction",
    "Farbkorrektur", "Strength: %.2f", "Stärke: %.2f", "Screen Ghosting",
    "Bildschirm-Ghosting", "Force Integer Scaling",
    "Erzwinge ganzzahlige Skalierung", "Stretch Screen to Fit",
    "Strecke Bildschirm", "Game Boy Color Palette", "Game Boy Color-Palette",
    "GB Palette %d", "GB-Palette %d", "Reset Palette to Defaults",
    "Stelle Standardpalette wieder her", ICON_FK_KEYBOARD_O " Keybinds",
    ICON_FK_KEYBOARD_O " Tastenbelegung", "Reset Default Keybinds",
    "Stelle Standardbelegung wieder her", ICON_FK_WRENCH " Advanced",
    ICON_FK_WRENCH " Erweitert", "Light Mode", "Helles Design",
    "Show Debug Tools", "Zeige Debug-Tools", "Adjust volume",
    "Passe Lautstärke an", "Show/Hide Menu Panel", "Zeige/verberge Menüleiste",
    "Rewind at 8x speed", "Spule mit 8-facher Geschwindigkeit zurück",
    "Rewind at 4x speed", "Spule mit 4-facher Geschwindigkeit zurück",
    "Toggle pause/play.\n When paused, the rom selection screen will be shown.",
    "Pausieren/fortsetzen. Die ROM-Auswahl wird bei Pausierung gezeigt.",
    "Run at 2x Speed", "Laufe mit 2-facher Geschwindigkeit",
    "Run at the fastest speed possible", "Laufe so schnell wie möglich",
    "Screen", "Bildschirm", "LCD Shader Init", "LCD-Shaderinitialisierung",
    "Menu", "Menü", "Copy as..", "Kopieren als...", "Current", "Aktuell",
    "Original", "Original", "Opacity", "Opazität",
    ICON_FK_HAND_O_RIGHT " Touch Control Settings",
    ICON_FK_HAND_O_RIGHT " Berührungseinstellungen", "Hide when inactive",
    "Verstecke bei Inaktivität", ICON_FK_FILE_O " Dump Memory to File",
    ICON_FK_FILE_O " Schreibe Speicherauszug in Datei", "Start Address",
    "Startadresse", "Size", "Größe", "Save Memory Dump",
    "Speichere Speicherauszug", ICON_FK_RANDOM " Last Branch Locations",
    ICON_FK_RANDOM " Letzte Sprungziele", "Opacity: %.2f", "Opazität: %.2f",
    "Step Instruction", "Nächster Befehl", "Step Frame", "Nächstes Frame",
    "Disconnect Log", "Trenne Log", ICON_FK_FOLDER_OPEN " Open File From Disk",
    ICON_FK_FOLDER_OPEN " Öffne Datei von Festplatte", "Exit File Browser",
    "Schließe Dateibrowser", "Go back to recently loaded games",
    "Gehe zu zuletzt geladenen Spielen", "Go to parent directory",
    "Gehe zum übergeordneten Verzeichnis", "UP", "HOCH", "DOWN", "RUNTER",
    "LEFT", "LINKS", "RIGHT", "RECHTS", "Reset Game", "Zurücksetzen", "Turbo A",
    "Turbo A", "Turbo B", "Turbo B", "Turbo X", "Turbo X", "Turbo Y", "Turbo Y",
    "Turbo L", "Turbo L", "Turbo R", "Turbo R", "Solar Sensor+",
    "Sonnensensor+", "Solar Sensor-", "Sonnensensor-", "Theme", "Thema",
    "Solar Sensor", "Sonnensensor", "Brightness: %.2f", "Helligkeit: %.2f",
    "Dark\0Light\0Black\0", "Dunkel\0Hell\0Schwarz\0",
    "Always Show Menu/Nav Bar", "Zeige Menü-/Navigationsleiste immer",
    "Language", "Sprache", "SPACE", "LEERTASTE", "ESCAPE", "ESCAPE", "ENTER",
    "EINGABE", "BACKSPACE", "BACKSPACE", "INSERT", "EINFÜGEN", "DELETE",
    "LÖSCHEN", "RIGHT", "RECHTS", "LEFT", "LINKS", "DOWN", "RUNTER", "UP",
    "HOCH", "LEFT_SHIFT", "SHIFT_LINKS", "LEFT_CONTROL", "CONTROL_LINKS",
    "LEFT_ALT", "ALT_LINKS", "LEFT_SUPER", "SUPER_LINKS", "RIGHT_SHIFT",
    "SHIFT_RECHTS", "RIGHT_CONTROL", "CONTROL_RECHTS", "RIGHT_ALT",
    "ALT_RECHTS", "RIGHT_SUPER", "SUPER_RECHTS", "MENU", "MENÜ",
    "Enable Turbo and Hold Button Modifiers",
    "Schalte Turbo- und Hold-Modifizierer ein", "Scale", "Skalierung",
    "Scale: %.2f", "Skalierung: %.2f", "GBA Color Correction Type",
    "GBA-Farbkorrekturtyp", ICON_FK_TEXT_HEIGHT " GUI",
    ICON_FK_TEXT_HEIGHT " Benutzeroberfläche", "Full Screen", "Vollbildschirm",
    ICON_FK_CODE_FORK " Additional Search Paths",
    ICON_FK_CODE_FORK " Weitere Suchpfade", "Save File/State Path", "Save-Pfad",
    "BIOS/Firmware Path", "BIOS-/Firmwarepfad",
    "Create new save files in Save Path", "Erstelle neues Save in Save-Pfad",
    ICON_FK_CROSSHAIRS " Located BIOS/Firmware Files",
    ICON_FK_CROSSHAIRS " BIOS-/Firmwaredateien gefunden",
    "Force GB games to run in DMG mode",
    "Zwinge GB-Spiele, im DMG-Modus zu laufen", "Enable HTTP Control Server",
    "Aktiviere HTTP-Kontrollserver", "Server Port", "Serverport",
    "Toggle Full Screen", "Vollbild ein/aus",
    "Can't find all needed BIOS/Boot ROM/Firmware Files.",
    "Nicht alle benötigten BIOS-/Boot-ROM-/Firmwaredateien konnten gefunden "
    "werden.",
    "Accuracy will suffer and some features won't work.",
    "Genauigkeit ist verringert und einige Funktionen werden nicht "
    "funkionieren.",
    // New in v3
    "Avoid NDS Touchscreen", "Meide NDS-Touchscreen", ICON_FK_PLUS " New",
    ICON_FK_PLUS " Neu" ICON_FK_KEY " Action Replay Codes",
    ICON_FK_KEY " Action Replay-Codes", "Create new files in paths",
    "Erstelle neue Dateien in Pfaden", "Cheat Code Path", "Cheatcode-Pfad",
    NULL, NULL};

// Italian translation by https://github.com/SimoneN64
static char *it_localization_array[] = {
    ICON_FK_FILE_O " Load Game", ICON_FK_FILE_O " Carica Gioco", "Up", "Sù",
    "Down", "Giù", "Left", "Sinistra", "Right", "Destra", "Start", "Start",
    "Select", "Select", "Fold Screen (NDS)", "Piega (NDS)", "Tap Screen (NDS)",
    "Tocca (NDS)", "Emulator " ICON_FK_PAUSE "/" ICON_FK_PLAY,
    "Emulatore " ICON_FK_PAUSE "/" ICON_FK_PLAY, "Emulator " ICON_FK_BACKWARD,
    "Emulatore " ICON_FK_BACKWARD, "Emulator " ICON_FK_FORWARD,
    "Emulatore " ICON_FK_FORWARD, "Emulator " ICON_FK_FAST_FORWARD,
    "Emulatore " ICON_FK_FAST_FORWARD, "Capture State 0", "Cattura Stato 0",
    "Restore State 0", "Ripristina Stato 0", "Capture State 1",
    "Cattura Stato 1", "Restore State 1", "Ripristina Stato 1",
    "Capture State 2", "Cattura Stato 2", "Restore State 2",
    "Ripristina Stato 2", "Capture State 3", "Cattura Stato 3",
    "Restore State 3", "Ripristina Stato 3", "Analog Up/Down",
    "Analogico Sù/Giù", "Analog Left/Right", "Analogico Sinistra/Destra",
    "Analog L", "Analogico L", "Analog R", "Analogico R",
    "Display FPS: %2.1f\n", "FPS dello schermo: %2.1f\n",
    "Emulation FPS: %2.1f\n", "FPS d'emulazione: %2.1f\n",
    ICON_FK_VOLUME_UP " Audio", ICON_FK_VOLUME_UP " Audio",
    "Left Audio Channel", "Canale Sinistro dell'Audio", "Right Audio Channel",
    "Canale Destro dell'Audio", "Channel 0", "Canale 0", "Channel 1",
    "Canale 1", "Channel 2", "Canale 2", "Channel 3", "Canale 3", "Channel 4",
    "Canale 4", "Channel 5", "Canale 5", "Channel 6", "Canale 6", "Channel 7",
    "Canale 7", "Channel 8", "Canale 8", "Channel 9", "Canale 9", "Channel A",
    "Canale A", "Channel B", "Canale B", "Channel C", "Canale C", "Channel D",
    "Canale D", "Channel E", "Canale E", "Channel F", "Canale F",
    "Channel 1 (Square)", "Canale 1 (Quadra)", "Channel 2 (Square)",
    "Canale 2 (Quadra)", "Channel 3 (Wave)", "Canale 3 (Tabella)",
    "Channel 4 (Noise)", "Canale 4 (Rumore)", "Channel A (FIFO)",
    "Canale A (FIFO)", "Channel B (FIFO)", "Canale B (FIFO)",
    "Audio Ring (Samples Available: %d)",
    "Anello Audio (Campioni disponibili: %d)",
    "Audio Watchdog Triggered %d Times", "Watch-dog Audio innescato %d volte",
    ICON_FK_INFO_CIRCLE " Build Info", ICON_FK_INFO_CIRCLE " Info Build",
    "Commit Hash:", "Hash del Commit:", ICON_FK_SERVER " Registers",
    ICON_FK_SERVER " Registri", ICON_FK_LIST_OL " Disassembly",
    ICON_FK_LIST_OL " Disassembly",
    ICON_FK_EXCHANGE " Read/Write Memory Address",
    ICON_FK_EXCHANGE " Indirizzo memoria Read/Write", "address", "indirizzo",
    "data (32 bit)", "dato (32 bit)", "data (16 bit)", "dato (16 bit)",
    "data (8 bit)", "dato (8 bit)", "data (signed 32b)", "dato (-/+32 bit)",
    "data (signed 16b)", "dato (-/+16 bit)", "data (signed 8b)",
    "dato (-/+8 bit)", ICON_FK_PENCIL_SQUARE_O " Memory",
    ICON_FK_PENCIL_SQUARE_O " Memoria", ICON_FK_AREA_CHART " Emulator Stats",
    ICON_FK_AREA_CHART " Statistiche Emulatore", "Show/Hide %s Panel\n",
    "Nascondi/mostra pannello %s\n", "Press new button " ICON_FK_SIGN_IN,
    "Premi il nuovo tasto " ICON_FK_SIGN_IN, "Move Axis ", "Asse Movimento ",
    "Not bound", "Non assegnato", "Hat %d %s", "Hat %d %s", "Analog %d %s",
    "Analogico %d %s", "Key %d", "Tasto %d", "Analog %d (%0.2f)",
    "Analogico %d (%0.2f)", "Load ROM from file (.gb, .gbc, .gba, .zip)",
    "Carica ROM da file (.gb, .gbc, .gba, .zip)",
    "You can also drag & drop a ROM to load it",
    "Puoi anche trascinare una ROM per caricarla",
    "Load ROM(.gb, .gbc, .gba, .zip), save(.sav), or GBA bios (gba_bios.bin) "
    "from file",
    "Carica una ROM(.gb, .gbc, .gba, .zip), salvataggio(.sav), o bios GBA "
    "(gba_bios.bin) da file",
    "You can also drag & drop a ROM/save file to load it",
    "Puoi anche trascinare una ROM/file di salvataggio per caricarla/o",
    "Open ROM", "Apri ROM", ICON_FK_CLOCK_O " Load Recently Played Game",
    ICON_FK_CLOCK_O " Carica Gioco giocato di recente",
    ICON_FK_DOWNLOAD " Export Save", ICON_FK_DOWNLOAD " Esporta Salvataggio",
    "No recently played games", "Nessun gioco giocato di recente",
    ICON_FK_GAMEPAD " Controllers", ICON_FK_GAMEPAD " Controller", "Controller",
    "Controller", "No Controller", "Nessun Controller",
    "Reset Default Controller Bindings",
    "Reimposta assegnazioni default per il controller", "Rumble Supported",
    "Rumble Supportato", "Rumble Not Supported", "Rumble Non Supportato",
    ICON_FK_FLOPPY_O " Save States", ICON_FK_FLOPPY_O " Salvataggi di Stato",
    "Save Slot %d", "Slot %d", "Capture", "Cattura", "Restore", "Ripristina",
    "This save state came from an incompatible build. SkyEmu has attempted to "
    "recover it, but there may be issues",
    "Questo salvataggio di stato deriva da una build incompatibile. SkyEmu ha "
    "provato a recuperarlo, ma potrebbero esserci problemi",
    ICON_FK_DESKTOP " Display Settings",
    ICON_FK_DESKTOP " Impostazioni Display", "Screen Shader", "Shader Schermo",
    "Pixelate\0Bilinear\0LCD\0LCD & Subpixels\0Smooth Upscale (xBRZ)\0",
    "Pixellato\0Bilineare\0LCD\0LCD & Subpixels\0Upscaling Liscio (xBRZ)\0",
    "Screen Rotation", "Rotazione Schermo",
    "0 degrees\00090 degrees\000180 degrees\000270 degrees\0",
    "0°\00090°\000180°\000270°\0", "Color Correction", "Correzione Colore",
    "Strength: %.2f", "Forza: %.2f", "Screen Ghosting", "Schermo Fantasma",
    "Force Integer Scaling", "Forza il ridimensionamento a numeri interi",
    "Stretch Screen to Fit", "Allarga lo schermo per riempire",
    "Game Boy Color Palette", "Palette Game Boy Color", "GB Palette %d",
    "Palette GB %d", "Reset Palette to Defaults", "Reimposta palette default",
    ICON_FK_KEYBOARD_O " Keybinds", ICON_FK_KEYBOARD_O " Assegnazione tasti",
    "Reset Default Keybinds", "Reimposta assegnazioni default per i tasti",
    ICON_FK_WRENCH " Advanced", ICON_FK_WRENCH " Avanzate", "Light Mode",
    "Modalità chiara", "Show Debug Tools", "Mostra strumenti di Debug",
    "Adjust volume", "Aggiusta il volume", "Show/Hide Menu Panel",
    "Mostra/Nascondi il pannello Menu", "Rewind at 8x speed",
    "Riavvolgi a velocità 8x", "Rewind at 4x speed", "Riavvolgi a velocità 4x",
    "Toggle pause/play.\n When paused, the rom selection screen will be shown.",
    "Alterna play/pausa.\n Quando in pausa, il dialogo di selezione della rom "
    "verrà mostrato.",
    "Run at 2x Speed", "Esegui a velocità 2x",
    "Run at the fastest speed possible", "Esegui quanto più veloce possibile",
    "Screen", "Schermo", "LCD Shader Init", "Inizializzazione shader LCD",
    "Menu", "Menu", "Copy as..", "Copia come..", "Current", "Attuale",
    "Original", "Originale", "Opacity", "Opacità",
    ICON_FK_HAND_O_RIGHT " Touch Control Settings",
    ICON_FK_HAND_O_RIGHT " Impostazioni controllo Touch", "Hide when inactive",
    "Nascondi quando inattivo", ICON_FK_FILE_O " Dump Memory to File",
    ICON_FK_FILE_O " Scarica contenuto della memoria su File", "Start Address",
    "Indirizzo di inizio", "Size", "Dimensione", "Save Memory Dump",
    "Salva contenuto della memoria", ICON_FK_RANDOM " Last Branch Locations",
    ICON_FK_RANDOM " Posizione dell'ultima diramazione", "Opacity: %.2f",
    "Opacità: %.2f", "Step Instruction", "Esegui istruzione", "Step Frame",
    "Esegui Frame", "Disconnect Log", "Disconnetti Log",
    ICON_FK_FOLDER_OPEN " Open File From Disk",
    ICON_FK_FOLDER_OPEN " Apri File Dal Disco", "Exit File Browser",
    "Esci dall'Esplora File", "Go back to recently loaded games",
    "Torna ai giochi caricati di recente", "Go to parent directory",
    "Torna alla cartella madre", "UP", "SÙ", "DOWN", "GIÙ", "LEFT", "SINISTRA",
    "RIGHT", "DESTRA", "Reset Game", "Riavvia Gioco", "Turbo A", "Turbo A",
    "Turbo B", "Turbo B", "Turbo X", "Turbo X", "Turbo Y", "Turbo Y", "Turbo L",
    "Turbo L", "Turbo R", "Turbo R", "Solar Sensor+", "Sensore Solare+",
    "Solar Sensor-", "Sensore Solare-", "Theme", "Tema", "Solar Sensor",
    "Sensore Solare", "Brightness: %.2f", "Luminosità: %.2f",
    "Dark\0Light\0Black\0", "Scuro\0Chiaro\0Nero\0", "Always Show Menu/Nav Bar",
    "Mostra barra Menu/Nav sempre", "Language", "Lingua", "SPACE", "SPAZIO",
    "ESCAPE", "ESC", "ENTER", "INVIO", "BACKSPACE", "BACKSPACE", "INSERT",
    "INSERT", "DELETE", "DELETE", "RIGHT", "DESTRA", "LEFT", "SINISTRA", "DOWN",
    "GIÙ", "UP", "SÙ", "LEFT_SHIFT", "Shift Sinistro", "LEFT_CONTROL",
    "Control Sinistro", "LEFT_ALT", "Alt Sinistro", "LEFT_SUPER",
    "Super Sinistro", "RIGHT_SHIFT", "Shift Destro", "RIGHT_CONTROL",
    "Control Destro", "RIGHT_ALT", "Alt Destro", "RIGHT_SUPER", "Super Destro",
    "MENU", "MENU", "Enable Turbo and Hold Button Modifiers",
    "Abilità modificatori tasti Turbo e Hold", "Scale", "Dimensione",
    "Scale: %.2f", "Dimensione %.2f", "GBA Color Correction Type",
    "Tipo correzione colore GBA", ICON_FK_TEXT_HEIGHT " GUI",
    ICON_FK_TEXT_HEIGHT " GUI", "Full Screen", "Schermo Intero",
    ICON_FK_CODE_FORK " Additional Search Paths",
    ICON_FK_CODE_FORK " Path Aggiuntivi per la Ricerca", "Save File/State Path",
    "Path salvataggi", "BIOS/Firmware Path", "Path BIOS",
    "Create new save files in Save Path",
    "Crea nuovi salvataggi di file nella Path dei salvataggi",
    ICON_FK_CROSSHAIRS " Located BIOS/Firmware Files",
    ICON_FK_CROSSHAIRS " File del BIOS/Firmware situati",
    "Force GB games to run in DMG mode",
    "Forza esecuzione dei giochi GB in modalità DMG",
    "Enable HTTP Control Server", "Abilità server di controllo tramite HTTP",
    "Server Port", "Porta Server", "Toggle Full Screen", "Full Screen",
    "Can't find all needed BIOS/Boot ROM/Firmware Files.",
    "Non ho trovato i file di Boot-ROM/BIOS/Firmware.",
    "Accuracy will suffer and some features won't work.",
    "L'accuratezza e alcune feature ne risentiranno.",
    // New in V3
    "Avoid NDS Touchscreen", "Evita il touchscreen del NDS",
    ICON_FK_PLUS " New", ICON_FK_PLUS " Nuovo",
    ICON_FK_KEY " Action Replay Codes", ICON_FK_KEY " Codici Action Replay",
    "Create new files in paths", "Crea nuovi file nei path", "Cheat Code Path",
    "Path dei trucchi", NULL, NULL};

// Russian translation by https://github.com/GreatA1exander
static char *ru_localization_array[] = {
    ICON_FK_FILE_O " Load Game", ICON_FK_FILE_O " Загрузить игру", "Up",
    "Вверх", "Down", "Вниз", "Left", "Лево", "Right", "Право", "Start",
    "Начинать", "Select", "Выбирать", "Fold Screen (NDS)", "Закрыть Эк. (NDS)",
    "Tap Screen (NDS)", "Нажать Эк. (NDS)",
    "Emulator " ICON_FK_PAUSE "/" ICON_FK_PLAY,
    "Эмулятор " ICON_FK_PAUSE "/" ICON_FK_PLAY, "Emulator " ICON_FK_BACKWARD,
    "Эмулятор " ICON_FK_BACKWARD, "Emulator " ICON_FK_FORWARD,
    "Эмулятор " ICON_FK_FORWARD, "Emulator " ICON_FK_FAST_FORWARD,
    "Эмулятор " ICON_FK_FAST_FORWARD, "Capture State 0", "Поймать Coc. 0",
    "Restore State 0", "Загрузить Coc. 0", "Capture State 1", "Поймать Coc. 1",
    "Restore State 1", "Загрузить Coc. 1", "Capture State 2", "Поймать Coc. 2",
    "Restore State 2", "Загрузить Coc. 2", "Capture State 3", "Поймать Coc. 3",
    "Restore State 3", "Загрузить Coc. 3", "Analog Up/Down",
    "Аналогичискый Вверх/Вниз", "Analog Left/Right", "Аналогичискый Лево/Право",
    "Analog L", "Аналогичискый L", "Analog R", "Аналогичискый R",
    "Display FPS: %2.1f\n", "Видимый FPS: %2.1f\n", "Emulation FPS: %2.1f\n",
    "Эмуляторскии FPS: %2.1f\n", ICON_FK_VOLUME_UP " Звук",
    ICON_FK_VOLUME_UP " Звук", "Left Audio Channel", "Левый звуковой канал",
    "Right Audio Channel", "Правый звуковой канал", "Channel 0", "Канал 0",
    "Channel 1", "Канал 1", "Channel 2", "Канал 2", "Channel 3", "Канал 3",
    "Channel 4", "Канал 4", "Channel 5", "Канал 5", "Channel 6", "Канал 6",
    "Channel 7", "Канал 7", "Channel 8", "Канал 8", "Channel 9", "Канал 9",
    "Channel A", "Канал A", "Channel B", "Канал B", "Channel C", "Канал C",
    "Channel D", "Канал D", "Channel E", "Канал E", "Channel F", "Канал F",
    "Channel 1 (Square)", "Канал 1 (Квадрат)", "Channel 2 (Square)",
    "Канал 2 (Квадрат)", "Channel 3 (Wave)", "Канал 3 (Волна)",
    "Channel 4 (Noise)", "Канал 4 (Шум)", "Channel A (FIFO)", "Канал A (FIFO)",
    "Channel B (FIFO)", "Канал B (FIFO)", "Audio Ring (Samples Available: %d)",
    "Звуковое кольцо (Доступны образцы: %d)",
    "Audio Watchdog Triggered %d Times",
    "Сработал сторожевой таймер аудио %d раз",
    ICON_FK_INFO_CIRCLE " Build Info",
    ICON_FK_INFO_CIRCLE " Информация о сборке",
    "Commit Hash:", "Хэш:", ICON_FK_SERVER " Registers",
    ICON_FK_SERVER " Регистры", ICON_FK_LIST_OL " Disassembly",
    ICON_FK_LIST_OL " Разборка", ICON_FK_EXCHANGE " Read/Write Memory Address",
    ICON_FK_EXCHANGE " Адрес памяти Read/Write", "address", "Адрес",
    "data (32 bit)", "Данные (32 bit)", "data (16 bit)", "Данные (16 bit)",
    "data (8 bit)", "Данные (8 bit)", "data (signed 32b)", "Данные (±32 bit)",
    "data (signed 16b)", "Данные (±16 bit)", "data (signed 8b)",
    "Данные (±8 bit)", ICON_FK_PENCIL_SQUARE_O " Memory",
    ICON_FK_PENCIL_SQUARE_O " Память", ICON_FK_AREA_CHART " Emulator Stats",
    ICON_FK_AREA_CHART " Статистики эмулятора", "Show/Hide %s Panel\n",
    "Показывать/Прятать Панель %s\n", "Press new button " ICON_FK_SIGN_IN,
    "Нажимать новую кнопку " ICON_FK_SIGN_IN, "Move Axis ", "Подвижная ось ",
    "Not bound", "Не привязана", "Hat %d %s", "Шапка %d %s", "Analog %d %s",
    "Аналог %d %s", "Key %d", "Клавиша %d", "Analog %d (%0.2f)",
    "Аналог %d (%0.2f)", "Load ROM from file (.gb, .gbc, .gba, .zip)",
    "Загрузить ROM из файла (.gb, .gbc, .gba, .zip)",
    "You can also drag & drop a ROM to load it",
    "Вы также можете перетащить ROM и загрузить его",
    "Load ROM(.gb, .gbc, .gba, .zip), save(.sav), or GBA bios (gba_bios.bin) "
    "from file",
    "Загрузить ROM(.gb, .gbc, .gba, .zip), сохраненный файл(.sav), или биос "
    "GBA (gba_bios.bin) из файла",
    "You can also drag & drop a ROM/save file to load it",
    "Вы также можете перетащить ROM/файл и загрузить его", "Open ROM",
    "Открыть ROM", ICON_FK_CLOCK_O " Load Recently Played Game",
    ICON_FK_CLOCK_O " Загрузить недавно сыгранную игру",
    ICON_FK_DOWNLOAD " Export Save",
    ICON_FK_DOWNLOAD " Экспорт файл сохранения", "No recently played games",
    "Нет недавно сыгранных игр", ICON_FK_GAMEPAD " Controllers",
    ICON_FK_GAMEPAD " Контроллеры", "Controller", "Контроллер", "No Controller",
    "Отсутствует Контроллер", "Reset Default Controller Bindings",
    "Сбросить привязки контроллера", "Rumble Supported",
    "Громыхание существует", "Rumble Not Supported", "Громыхание не существует",
    ICON_FK_FLOPPY_O " Save States", ICON_FK_FLOPPY_O " Сохранение состояния",
    "Save Slot %d", "Слот %d", "Capture", "Поймать", "Restore", "Загрузить",
    "This save state came from an incompatible build. SkyEmu has attempted to "
    "recover it, but there may be issues",
    "Это состояние сохранения получено из несовместимой сборки. SkyEmu "
    "попытался восстановить его, но могут возникнуть проблемы",
    ICON_FK_DESKTOP " Display Settings",
    ICON_FK_DESKTOP " Настройки отображения", "Screen Shader", "Шейдер экрана",
    "Pixelate\0Bilinear\0LCD\0LCD & Subpixels\0Smooth Upscale (xBRZ)\0",
    "Пикселизация\0Билинейный\0LCD\0LCD & субпиксель\0Плавно увеличиват "
    "разрешение (xBRZ)\0",
    "Screen Rotation", "Вращение экрана",
    "0 degrees\00090 degrees\000180 degrees\000270 degrees\0",
    "0°\00090°\000180°\000270°\0", "Color Correction", "Коррекция цвета",
    "Сила: %.2f", "Forza: %.2f", "Screen Ghosting", "Призрак экрана",
    "Force Integer Scaling", "Целочисленное разрешение мандата",
    "Stretch Screen to Fit", "Растянуть экран по размеру",
    "Game Boy Color Palette", "Палитра Game Boy Color", "GB Palette %d",
    "Палитра GB %d", "Reset Palette to Defaults", "Сбросить палитру",
    ICON_FK_KEYBOARD_O " Keybinds", ICON_FK_KEYBOARD_O " Связки клавиш",
    "Reset Default Keybinds", "Сбросить сочетания клавиш",
    ICON_FK_WRENCH " Advanced", ICON_FK_WRENCH " Сложный", "Light Mode",
    "Яркий режим", "Show Debug Tools", "Показать инструменты отладки",
    "Adjust volume", "Отрегулировать громкость", "Show/Hide Menu Panel",
    "Показать/скрыть панель меню", "Rewind at 8x speed",
    "Перемотка назад с 8-кратной скоростью", "Rewind at 4x speed",
    "Перемотка назад с 4-кратной скоростью",
    "Toggle pause/play.\n When paused, the rom selection screen will be shown.",
    "Переключить паузу/пуск.\n При паузе будет показан экран выбора ROM.",
    "Run at 2x Speed", "Играть с удвоенной скоростью",
    "Run at the fastest speed possible", "Играть на максимальной скорости",
    "Screen", "Экран", "LCD Shader Init", "Инициализация шейдера LCD", "Menu",
    "Меню", "Copy as..", "Скопировать как..", "Current", "Действительный",
    "Original", "Оригинал", "Opacity", "Непрозрачность",
    ICON_FK_HAND_O_RIGHT " Touch Control Settings",
    ICON_FK_HAND_O_RIGHT " Настройки касания", "Hide when inactive",
    "Прятать когда неактивен", ICON_FK_FILE_O " Dump Memory to File",
    ICON_FK_FILE_O " Дамп памяти в файл", "Start Address", "Начальный адрес",
    "Size", "Размер", "Save Memory Dump", "Сохранить дамп памяти",
    ICON_FK_RANDOM " Last Branch Locations",
    ICON_FK_RANDOM " Местоположения последней ветки", "Opacity: %.2f",
    "Непрозрачность: %.2f", "Step Instruction", "Шаг инструкция", "Step Frame",
    "Шаг Рамки", "Disconnect Log", "Выключить журнал",
    ICON_FK_FOLDER_OPEN " Open File From Disk",
    ICON_FK_FOLDER_OPEN " Открыть файл с диска", "Exit File Browser",
    "Выйти файлового браузера", "Go back to recently loaded games",
    "Вернуться к недавно загруженным играм", "Go to parent directory",
    "Перейти в родительский папку", "UP", "ВВЕРХ", "DOWN", "ВНИЗ", "LEFT",
    "ЛЕВО", "RIGHT", "ПРАВО", "Reset Game", "Перезапуск игри", "Turbo A",
    "Турбо A", "Turbo B", "Турбо B", "Turbo X", "Турбо X", "Turbo Y", "Турбо Y",
    "Turbo L", "Турбо L", "Turbo R", "Турбо R", "Solar Sensor+", "Солнечный+",
    "Solar Sensor-", "Солнечный-", "Theme", "Тема", "Solar Sensor",
    "Солнечный датчик", "Brightness: %.2f", "Яркость: %.2f",
    "Dark\0Light\0Black\0", "Тьма\0Свет\0Черный\0", "Always Show Menu/Nav Bar",
    "Всегда показывать панель меню/навигации", "Language", "Язык", "SPACE",
    "ПРОБЕЛ", "ESCAPE", "ESC", "ENTER", "ENTER", "BACKSPACE", "BACK", "INSERT",
    "INSERT", "DELETE", "DELETE", "RIGHT", "ПРАВО", "LEFT", "ЛЕВО", "DOWN",
    "ВНИЗ", "UP", "ВВЕРХ", "LEFT_SHIFT", "Левый шифт", "LEFT_CONTROL",
    "Левый контроль", "LEFT_ALT", "Левый альт", "LEFT_SUPER", "Левый супер",
    "RIGHT_SHIFT", "Правый шифт", "RIGHT_CONTROL", "Правый контроль",
    "RIGHT_ALT", "Правый альт", "RIGHT_SUPER", "Правый супер", "MENU", "MENU",
    "Enable Turbo and Hold Button Modifiers", "Включить Turbo и Hold", "Scale",
    "Масштаб", "Scale: %.2f", "Масштаб %.2f", "GBA Color Correction Type",
    "Тип коррекции цвета GBA", ICON_FK_TEXT_HEIGHT " GUI",
    ICON_FK_TEXT_HEIGHT " GUI", "Full Screen", "Полноэкранный",
    ICON_FK_CODE_FORK " Additional Search Paths",
    ICON_FK_CODE_FORK " Дополнительные пути поиска", "Save File/State Path",
    "Путь сохранений", "BIOS/Firmware Path", "Путь BIOS",
    "Create new save files in Save Path",
    "Создайте новые файлы сохранения в пути сохранения",
    ICON_FK_CROSSHAIRS " Located BIOS/Firmware Files",
    ICON_FK_CROSSHAIRS " Найдены файлы BIOS/Firmware",
    "Force GB games to run in DMG mode",
    "Заставить игры GB работать в режиме DMG", "Enable HTTP Control Server",
    "Включить сервер управления HTTP", "Server Port", "Порт сервер",
    "Toggle Full Screen", "Полноэкранный",
    "Can't find all needed BIOS/Boot ROM/Firmware Files.",
    "Не удается найти все файлы BIOS/Boot ROM/Firmware.",
    "Accuracy will suffer and some features won't work.",
    "Точность будет страдать, и некоторые функции не будут работать.",
    // New in V3
    "Avoid NDS Touchscreen", "Не используйте второй экран NDS",
    ICON_FK_PLUS " New", ICON_FK_PLUS " Новый",
    ICON_FK_KEY " Action Replay Codes", ICON_FK_KEY " Коды Action Replay",
    "Create new files in paths", "Создавать новые файлы в путях",
    "Cheat Code Path", "Путь к чит-кодам", NULL, NULL};

char **localization_map = NULL;
size_t localization_size = 0;
int se_get_default_language();

int se_localize_cmp(const void *a, const void *b) {
  return strcmp(((const char **)a)[0], ((const char **)b)[0]);
}
void se_set_language(int language_enum) {
  char **new_map = NULL;
  if (language_enum == SE_LANG_DEFAULT)
    language_enum = se_get_default_language();
  if (language_enum == SE_LANG_CHINESE)
    new_map = zh_localization_array;
  if (language_enum == SE_LANG_ARMENIAN)
    new_map = hy_localization_array;
  if (language_enum == SE_LANG_GREEK)
    new_map = gr_localization_array;
  if (language_enum == SE_LANG_DUTCH)
    new_map = nl_localization_array;
  if (language_enum == SE_LANG_DANISH)
    new_map = da_localization_array;
  if (language_enum == SE_LANG_GERMAN)
    new_map = de_localization_array;
  if (language_enum == SE_LANG_ITALIAN)
    new_map = it_localization_array;
  if (language_enum == SE_LANG_RUSSIAN)
    new_map = ru_localization_array;
  if (new_map != localization_map) {
    localization_map = new_map;
    localization_size = 0;
    if (localization_map) {
      while (localization_map[localization_size * 2])
        ++localization_size;
      qsort(localization_map, localization_size, sizeof(const char *) * 2,
            se_localize_cmp);
    }
  }
}
int se_convert_locale_to_enum(const char *clocale) {
  // Convert the detected language to lowercase for easier comparison
  char lowercase_locale[128]; // Assuming the language code won't exceed 16
                              // characters
  int i = 0;

  // Normalize case, remove country code, and code page
  while (clocale[i] != '\0' && clocale[i] != '.' && clocale[i] != '_' &&
         clocale[i] != '-' && i < 127) {
    lowercase_locale[i] = tolower(clocale[i]);
    i++;
  }
  lowercase_locale[i] = '\0';

  // Match the language to the enumeration based on ISO 639-1 and ISO 639-2
  // codes See (https://www.loc.gov/standards/iso639-2/php/code_list.php)
  if (strcmp(lowercase_locale, "en") == 0 ||
      strcmp(lowercase_locale, "eng") == 0 ||
      strcmp(lowercase_locale, "english") == 0) {
    return SE_LANG_ENGLISH;
  } else if (strcmp(lowercase_locale, "ar") == 0 ||
             strcmp(lowercase_locale, "ara") == 0 ||
             strcmp(lowercase_locale, "arabic") == 0) {
    return SE_LANG_ARABIC;
  } else if (strcmp(lowercase_locale, "hy") == 0 ||
             strcmp(lowercase_locale, "arm") == 0 ||
             strcmp(lowercase_locale, "armenian") == 0) {
    return SE_LANG_ARMENIAN;
  } else if (strcmp(lowercase_locale, "bn") == 0 ||
             strcmp(lowercase_locale, "ben") == 0 ||
             strcmp(lowercase_locale, "bengali") == 0) {
    return SE_LANG_BENGALI;
  } else if (strcmp(lowercase_locale, "zh") == 0 ||
             strcmp(lowercase_locale, "chi") == 0 ||
             strcmp(lowercase_locale, "zho") == 0 ||
             strcmp(lowercase_locale, "chinese") == 0) {
    return SE_LANG_CHINESE;
  } else if (strcmp(lowercase_locale, "da") == 0 ||
             strcmp(lowercase_locale, "dan") == 0 ||
             strcmp(lowercase_locale, "danish") == 0) {
    return SE_LANG_DANISH;
  } else if (strcmp(lowercase_locale, "nl") == 0 ||
             strcmp(lowercase_locale, "dut") == 0 ||
             strcmp(lowercase_locale, "dutch") == 0) {
    return SE_LANG_DUTCH;
  } else if (strcmp(lowercase_locale, "fr") == 0 ||
             strcmp(lowercase_locale, "fre") == 0 ||
             strcmp(lowercase_locale, "fra") == 0 ||
             strcmp(lowercase_locale, "french") == 0) {
    return SE_LANG_FRENCH;
  } else if (strcmp(lowercase_locale, "de") == 0 ||
             strcmp(lowercase_locale, "ger") == 0 ||
             strcmp(lowercase_locale, "deu") == 0 ||
             strcmp(lowercase_locale, "german") == 0) {
    return SE_LANG_GERMAN;
  } else if (strcmp(lowercase_locale, "el") == 0 ||
             strcmp(lowercase_locale, "gre") == 0 ||
             strcmp(lowercase_locale, "ell") == 0 ||
             strcmp(lowercase_locale, "greek") == 0) {
    return SE_LANG_GREEK;
  } else if (strcmp(lowercase_locale, "hi") == 0 ||
             strcmp(lowercase_locale, "hin") == 0 ||
             strcmp(lowercase_locale, "hindi") == 0) {
    return SE_LANG_HINDI;
  } else if (strcmp(lowercase_locale, "it") == 0 ||
             strcmp(lowercase_locale, "ita") == 0 ||
             strcmp(lowercase_locale, "italian") == 0) {
    return SE_LANG_ITALIAN;
  } else if (strcmp(lowercase_locale, "ja") == 0 ||
             strcmp(lowercase_locale, "jpn") == 0 ||
             strcmp(lowercase_locale, "japanese") == 0) {
    return SE_LANG_JAPANESE;
  } else if (strcmp(lowercase_locale, "ko") == 0 ||
             strcmp(lowercase_locale, "kor") == 0 ||
             strcmp(lowercase_locale, "korean") == 0) {
    return SE_LANG_KOREAN;
  } else if (strcmp(lowercase_locale, "pt") == 0 ||
             strcmp(lowercase_locale, "por") == 0 ||
             strcmp(lowercase_locale, "portuguese") == 0) {
    return SE_LANG_PORTUGESE;
  } else if (strcmp(lowercase_locale, "ru") == 0 ||
             strcmp(lowercase_locale, "rus") == 0 ||
             strcmp(lowercase_locale, "russian") == 0) {
    return SE_LANG_RUSSIAN;
  } else if (strcmp(lowercase_locale, "es") == 0 ||
             strcmp(lowercase_locale, "spa") == 0 ||
             strcmp(lowercase_locale, "spanish") == 0) {
    return SE_LANG_SPANISH;
  }
  return SE_LANG_DEFAULT;
}
const char *se_language_string(int language_enum) {
  switch (language_enum) {
  case SE_LANG_DEFAULT:
    return se_localize("Default");
  case SE_LANG_ENGLISH:
    return "English";
  case SE_LANG_DUTCH:
    return "Nederlands";
  case SE_LANG_DANISH:
    return "Dansk";
  case SE_LANG_GERMAN:
    return "Deutsch";
  case SE_LANG_ITALIAN:
    return "Italiano";
    // These languages require unicode support to represent correctly
#ifdef UNICODE_GUI
  case SE_LANG_CHINESE:
    return "中文";
  case SE_LANG_ARMENIAN:
    return "Հայերեն";
  case SE_LANG_GREEK:
    return "Ελληνικά";
  case SE_LANG_RUSSIAN:
    return "Русский";
#endif
  }
  return "";
}
#ifdef PLATFORM_ANDROID
extern void se_android_get_language(char *language_buffer, size_t buffer_size);
#endif
int se_get_default_language() {
  static int default_lang = SE_LANG_DEFAULT;
  if (default_lang == SE_LANG_DEFAULT) {
#if defined(PLATFORM_IOS) || defined(PLATFORM_MACOS)
    // Try to get from CF Locale
    if (default_lang == SE_LANG_DEFAULT) {
      char lang_buffer[128];
      CFArrayRef langs = CFLocaleCopyPreferredLanguages();
      CFStringRef lang_code = CFArrayGetValueAtIndex(langs, 0);
      CFStringGetCString(lang_code, lang_buffer, 128, kCFStringEncodingUTF8);
      default_lang = se_convert_locale_to_enum(lang_buffer);
      if (default_lang != SE_LANG_DEFAULT)
        printf("Detected CF locale language: %s (enum: %s)\n", lang_buffer,
               se_language_string(default_lang));
    }
#endif
#ifdef PLATFORM_ANDROID
    // Try to get from JNI
    if (default_lang == SE_LANG_DEFAULT) {
      char lang_buffer[128];
      se_android_get_language(lang_buffer, sizeof(lang_buffer));
      default_lang = se_convert_locale_to_enum(lang_buffer);
      if (default_lang != SE_LANG_DEFAULT)
        printf("Detected language from JNI: %s (enum: %s)\n", lang_buffer,
               se_language_string(default_lang));
    }
#endif
    // Try to get from environment
    if (default_lang == SE_LANG_DEFAULT) {
      char *clocale = getenv("LANG");
      if (clocale)
        default_lang = se_convert_locale_to_enum(clocale);
      if (default_lang != SE_LANG_DEFAULT)
        printf("Detected environment locale language: %s (enum: %s)\n", clocale,
               se_language_string(default_lang));
    }

    // Try to get from setlocale
    if (default_lang == SE_LANG_DEFAULT) {
      setlocale(LC_ALL, "");
      char *clocale = setlocale(LC_ALL, NULL);
      if (clocale)
        default_lang = se_convert_locale_to_enum(clocale);
      if (default_lang != SE_LANG_DEFAULT)
        printf("Detected C locale language: %s (enum: %s)\n", clocale,
               se_language_string(default_lang));
    }

    if (default_lang == SE_LANG_DEFAULT) {
      printf("Couldn't detect language, defaulting to English\n");
      default_lang = SE_LANG_ENGLISH;
    }
#ifdef PLATFORM_WINDOWS
    // Needed to let windows open files from UTF-8 paths
    setlocale(LC_ALL, ".65001");
#endif
  }
  return default_lang;
}
const char *se_localize(const char *string) {
  if (localization_map == NULL)
    return string;
  const char **result =
      (const char **)bsearch(&string, localization_map, localization_size,
                             sizeof(const char *) * 2, se_localize_cmp);
  if (!result)
    return string;
  else
    return result[1];
}
