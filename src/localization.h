#ifndef LOCALIZATION_H
#define LOCALIZATION_H

#define SE_LANG_DEFAULT 0
#define SE_LANG_ENGLISH 1
#define SE_LANG_ARABIC  2
#define SE_LANG_ARMENIAN 3 
#define SE_LANG_BENGALI 4
#define SE_LANG_CHINESE 5
#define SE_LANG_FRENCH  6
#define SE_LANG_GERMAN  7
#define SE_LANG_GREEK   8
#define SE_LANG_HINDI   9
#define SE_LANG_JAPANESE 10
#define SE_LANG_KOREAN  11
#define SE_LANG_ITALIAN 12
#define SE_LANG_PORTUGESE 13
#define SE_LANG_RUSSIAN 14
#define SE_LANG_SPANISH 15
#define SE_MAX_LANG_VALUE 16

void se_set_language(int language_enum);//i.e. SE_LANG_ENGLISH
const char* se_language_string(int language_enum);//returns "" if language is not supported
const char* se_localize(const char* string);

#endif