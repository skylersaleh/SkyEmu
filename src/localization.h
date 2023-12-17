#ifndef LOCALIZATION_H
#define LOCALIZATION_H

#define SE_LANG_DEFAULT   0
#define SE_LANG_ENGLISH   5
#define SE_LANG_ARABIC    10
#define SE_LANG_ARMENIAN  15
#define SE_LANG_BENGALI   20
#define SE_LANG_CHINESE   25
#define SE_LANG_DANISH    27
#define SE_LANG_DUTCH     30
#define SE_LANG_FRENCH    35
#define SE_LANG_GERMAN    40
#define SE_LANG_GREEK     45
#define SE_LANG_HINDI     50
#define SE_LANG_ITALIAN   65
#define SE_LANG_JAPANESE  55
#define SE_LANG_KOREAN    60
#define SE_LANG_PORTUGESE 70
#define SE_LANG_RUSSIAN   75
#define SE_LANG_SPANISH   80
#define SE_MAX_LANG_VALUE 86

void        se_set_language(int language_enum);    // i.e. SE_LANG_ENGLISH
const char* se_language_string(int language_enum); // returns "" if language is not supported
const char* se_localize(const char* string);
int         se_convert_locale_to_enum(const char* clocale);

#endif