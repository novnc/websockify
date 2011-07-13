#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "realpath.h"

char * realpath( const char * path, char * buffer )
{
	char tmp[FILENAME_MAX];
	size_t len;

	len = GetFullPathNameA( path, FILENAME_MAX, tmp, NULL );
	if ( len >= 0 )
	{
		if ( buffer == NULL ) buffer = malloc(len+1);
		strcpy_s( buffer, len + 1, tmp );
		return buffer;
	}
	else return NULL;
}