 
#define DATA_SIZE 271360
void spawn(void * buffer, int length, char * key);

typedef struct {
	int  offset;
	int  length;
	char key[4];
	int  gmh_offset;
	int  gpa_offset;
	char payload[DATA_SIZE];
} phear;

extern char data[DATA_SIZE];
