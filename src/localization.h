#ifndef LOCALIZATION_H
#define LOCALIZATION_H

enum {
    SE_LANG_DEFAULT,
    SE_LANG_ENGLISH,
    SE_LANG_ARABIC,
    SE_LANG_ARMENIAN,
    SE_LANG_BENGALI,
    SE_LANG_CHINESE,
    SE_LANG_FRENCH,
    SE_LANG_GERMAN,
    SE_LANG_GREEK,
    SE_LANG_HINDI,
    SE_LANG_JAPANESE,
    SE_LANG_KOREAN,
    SE_LANG_ITALIAN,
    SE_LANG_PORTUGESE,
    SE_LANG_RUSSIAN,
    SE_LANG_SPANISH,
    SE_MAX_LANG_VALUE
};

void se_set_language(int language_enum);//i.e. SE_LANG_ENGLISH
const char* se_language_string(int language_enum);//returns "" if language is not supported
const char* se_localize(const char* string);

#endif