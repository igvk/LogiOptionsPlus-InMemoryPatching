#include <cctype>
#include "utilities.hpp"

// returns TRUE if text string matches glob-like pattern with * and ?
// glob string should be in lowercase
bool glob_match(const char* text, const char* glob)
{
    const char* text_backup = nullptr;
    const char* glob_backup = nullptr;
    while (*text != '\0')
    {
        if (*glob == '*')
        {
            // new star-loop: backup positions in pattern and text
            text_backup = text;
            glob_backup = ++glob;
        }
        else if ((*glob == '?' && *text != '/') || *glob == tolower(*text))
        {
            // ? matched any character except /, or we matched the current non-NUL character
            text++;
            glob++;
        }
        else
        {
            if (glob_backup == nullptr || *text_backup == '/')
                return false;
            // star-loop: backtrack to the last * but do not jump over /
            text = ++text_backup;
            glob = glob_backup;
        }
    }
    // ignore trailing stars
    while (*glob == '*')
        glob++;
    // at end of text means success if nothing else is left to match
    return *glob == '\0';
}
