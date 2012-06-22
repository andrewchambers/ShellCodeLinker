#include <stdio.h>
#include <stdlib.h>


#include <sys/mman.h>


#define BUFFSIZE 4096

int
main (int argc, char *argv[])
{
    
    char * assembly = malloc(BUFFSIZE);
    if(!assembly){
        puts("malloc failed!");
        return 1;
    }
    
    FILE * f;
    f = fopen("exampleshellcode.bin","rb");
    
    if(!f){
        puts("failed to open file");
        return 1;
    }
    
    int ind = 0;
    
    while(1) {
        int c;
        c = fgetc(f);
        
        if(c == EOF)
            break;
        
        if(ind >= BUFFSIZE){
            puts("assembly too large for buffer");
            close(f);
            return 1;
        }
        
        assembly[ind++] = c;
    }
    
    close(f);
    
    printf("finished reading %d bytes into memory\n",ind);
    
    
    puts("making the malloced page executable!");
    if( mprotect(assembly - ((int)assembly % getpagesize()),BUFFSIZE,PROT_READ|PROT_WRITE|PROT_EXEC) ){
        perror("mprotect failed");
        puts("failed to set memory executable");
        return 1;
    }
    
    puts("casting shellcode to pointer, calling, and printing return");
    puts( ( (char *(*)()) assembly ) () );

    
    return 0;
}
