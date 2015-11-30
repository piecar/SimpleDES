#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#define BUFFSIZE 8
#define KEYSIZE 10

void syserr(char* msg) { perror(msg); exit(-1); }
uint8_t fk(uint8_t ip, uint8_t key);
uint8_t IP(uint8_t ip);
uint8_t swap(uint8_t fkOut);
uint8_t invip(uint8_t chain);

// 
int main(int argc, char* argv[])
{
  int decrypt;
  int i;
  FILE * fp;
  FILE * wfp;
  uint8_t ip, ipinv, k1, k2, initvec;
  char char0 = '0';
  char * ikey;
  char buffer;

  if(argc != 5 && argc != 6) {
    fprintf(stderr, "Usage: %s <init_key> <init_vector> <original_file> <result_file>\nUsage: %s [-d] <init_key> <init_vector> <original_file> <result_file", argv[0], argv[0]);
    return 1;
  }
  
  if(!strcmp(argv[1], "-d"))
    decrypt = 1;
  else
    decrypt = 0;
  if(!decrypt){
  	//Make k1
  	ikey = malloc(sizeof(char)*KEYSIZE);
  	sscanf(argv[1], "%s", ikey);
  	for (i=0; i < 10; i++){
  		ikey[i] = ikey[i] - char0;
  	}  	  	
  	char tkey[10];
  	
  	/// do P10 rearrange
  	tkey[0] = ikey[2];
  	tkey[1] = ikey[4];
  	tkey[2] = ikey[1];
  	tkey[3] = ikey[6];
  	tkey[4] = ikey[3];
  	tkey[5] = ikey[9];
  	tkey[6] = ikey[0];
  	tkey[7] = ikey[8];
  	tkey[8] = ikey[7];
  	tkey[9] = ikey[5];
  	/// do circular left shift
  	tkey[0] = ikey[4];
  	tkey[1] = ikey[1];
  	tkey[2] = ikey[6];
  	tkey[3] = ikey[3];
  	tkey[4] = ikey[2];
  	tkey[5] = ikey[0];
  	tkey[6] = ikey[8];
  	tkey[7] = ikey[7];
  	tkey[8] = ikey[5];
  	tkey[9] = ikey[9];
  	
  	k1 =  (tkey[2] << 6) | (tkey[3] << 4) | (tkey[4] << 2) | (tkey[5]) << 7| 
  				(tkey[6] << 5) | (tkey[7] << 3) | (tkey[8])      | (tkey[9] << 1);
  	// Make k2
  	tkey[0] = ikey[1];
  	tkey[1] = ikey[6];
  	tkey[2] = ikey[3];
  	tkey[3] = ikey[2];
  	tkey[4] = ikey[4];
  	tkey[5] = ikey[8];
  	tkey[6] = ikey[7];
  	tkey[7] = ikey[5];
  	tkey[8] = ikey[9];
  	tkey[9] = ikey[0];
  	k2 =  (tkey[2] << 6) | (tkey[3] << 4) | (tkey[4] << 2) | (tkey[5] << 7)| 
  				(tkey[6] << 5) | (tkey[7] << 3) | (tkey[8])      | (tkey[9] << 1);
  	
  	//File Ops
  	fp = fopen(argv[3], "r");
  	wfp = fopen(argv[4], "w");
  	fseek(fp, SEEK_SET, 0);
  	fseek(wfp, SEEK_SET, 0);
		int bytes_read = fread(&buffer, 1, 1, fp);
  	
  	//Set up Initialization Vector
  	char * ivec;
  	initvec = 0;
  	ivec = malloc(sizeof(char)*BUFFSIZE);
  	sscanf(argv[2], "%s", ivec);
  	for (i=0; i < 8; i++){
  		ivec[i] = ivec[i] - char0;
  	}
  	for(i=7; i>=0; i--){
  		initvec = initvec | (ivec[i] << (7-i));
  	}
  	buffer = buffer ^ initvec;
  	
		// Plain text permutations and functions
		ip = IP(buffer);
		/*
		printf("IP is: ");
  	for(i=7; i>=0; i--){
  		printf("%d", (ip >> i) & 0x01);
  	}
  	printf("\n");
  	*/
	  
	  uint8_t fkOut = fk(ip, k1); // Do the fk process with k1
		
		uint8_t fksw = swap(fkOut);
		fksw = fk(fksw, k2); // Do the fk process again with k2
		ipinv = invip(fksw); // Inverse IP function
		int bytes_writ = fwrite(&ipinv, 1, 1, wfp);
		if(bytes_writ < 0) syserr("Could not writ to file");
				 		
		while(1){
			bytes_read = fread(&buffer, 1, 1, fp);
  		
			if(bytes_read == 0){
				fclose(fp);
				fclose(wfp);
				break;
			}
			ip = IP(buffer ^ ipinv); // CBC done here
			fkOut = fk(ip, k1);
			fksw = swap(fkOut);
			fksw = fk(fksw, k2);
			ipinv = invip(fksw);
			bytes_writ = fwrite(&ipinv, 1, 1, wfp);
			if(bytes_writ < 0) syserr("Could not writ to file");
		}	
  }
  else{							//DECRYPT
  	//Make k1
  	ikey = malloc(sizeof(char)*KEYSIZE);
  	sscanf(argv[2], "%s", ikey);
  	for (i=0; i < 10; i++){
  		ikey[i] = ikey[i] - char0;
  	}  	  	
  	char tkey[10];
  	
  	/// do P10 rearrange
  	tkey[0] = ikey[2];
  	tkey[1] = ikey[4];
  	tkey[2] = ikey[1];
  	tkey[3] = ikey[6];
  	tkey[4] = ikey[3];
  	tkey[5] = ikey[9];
  	tkey[6] = ikey[0];
  	tkey[7] = ikey[8];
  	tkey[8] = ikey[7];
  	tkey[9] = ikey[5];
  	/// do circular left shift
  	tkey[0] = ikey[4];
  	tkey[1] = ikey[1];
  	tkey[2] = ikey[6];
  	tkey[3] = ikey[3];
  	tkey[4] = ikey[2];
  	tkey[5] = ikey[0];
  	tkey[6] = ikey[8];
  	tkey[7] = ikey[7];
  	tkey[8] = ikey[5];
  	tkey[9] = ikey[9];
  	
  	k1 =  (tkey[2] << 6) | (tkey[3] << 4) | (tkey[4] << 2) | (tkey[5]) << 7| 
  				(tkey[6] << 5) | (tkey[7] << 3) | (tkey[8])      | (tkey[9] << 1);
  	  		
  	// Make k2
  	tkey[0] = ikey[1];
  	tkey[1] = ikey[6];
  	tkey[2] = ikey[3];
  	tkey[3] = ikey[2];
  	tkey[4] = ikey[4];
  	tkey[5] = ikey[8];
  	tkey[6] = ikey[7];
  	tkey[7] = ikey[5];
  	tkey[8] = ikey[9];
  	tkey[9] = ikey[0];
  	k2 =  (tkey[2] << 6) | (tkey[3] << 4) | (tkey[4] << 2) | (tkey[5] << 7)| 
  				(tkey[6] << 5) | (tkey[7] << 3) | (tkey[8])      | (tkey[9] << 1);
  				
  	//File Ops
  	fp = fopen(argv[4], "r");
  	wfp = fopen(argv[5], "w");
  	fseek(fp, SEEK_SET, 0);
  	fseek(wfp, SEEK_SET, 0);
		int bytes_read = fread(&buffer, 1, 1, fp);
		
		//Set up Initialization Vector
  	char * ivec;
  	initvec = 0;
  	ivec = malloc(sizeof(char)*BUFFSIZE);
  	sscanf(argv[3], "%s", ivec);
  	for (i=0; i < 8; i++){
  		ivec[i] = ivec[i] - char0;
  	}
  	for(i=7; i>=0; i--){
  		initvec = initvec | (ivec[i] << (7-i));
  	}
  	uint8_t cbcDec = buffer;
  	
  	// cipher text permutations and functions
		ip = IP(buffer);
		/*
		printf("IP is: ");
  	for(i=7; i>=0; i--){
  		printf("%d", (ip >> i) & 0x01);
  	}
  	printf("\n");
	  */
	  uint8_t fkOut = fk(ip, k2); // Do the fk process with k1
		
		uint8_t fksw = swap(fkOut);
		fksw = fk(fksw, k1); // Do the fk process again with k2
		ipinv = invip(fksw); // Inverse IP function
  	ipinv = ipinv ^ initvec;
		int bytes_writ = fwrite(&ipinv, 1, 1, wfp);
		if(bytes_writ < 0) syserr("Could not writ to file");
		initvec = cbcDec;
				 		
		while(1){
			bytes_read = fread(&buffer, 1, 1, fp);
			if(bytes_read == 0){
				fclose(fp);
				fclose(wfp);
				break;
			}
			ip = IP(buffer);
			fkOut = fk(ip, k2);
			fksw = swap(fkOut);
			fksw = fk(fksw, k1);
			ipinv = invip(fksw);
			ipinv = initvec ^ ipinv;
			bytes_writ = fwrite(&ipinv, 1, 1, wfp);
			if(bytes_writ < 0) syserr("Could not writ to file");
			initvec = buffer;
		}	
  }
  
  return 0;
}

uint8_t fk(uint8_t ip, uint8_t key){
	uint8_t ep, epxk1, row, col, tp4, p4;
	uint8_t s0[4][4] = {
  	{1, 0, 3, 2},
  	{3, 2, 1, 0},
  	{0, 2, 1, 3},
  	{3, 1, 3, 2}
  };
  uint8_t s1[4][4] = {
  	{0, 1, 2, 3},
  	{2, 0, 1, 3},
  	{3, 0, 1, 0},
  	{2, 1, 0, 3}
  };
  ep = (ip & 0x08) << 3 | (ip & 0x04) << 1 |
			 (ip & 0x02) << 1 | (ip & 0x01) << 1 |
			 (ip & 0x08) >> 3 | (ip & 0x04) << 3 |
			 (ip & 0x02) << 3 | (ip & 0x01) << 7 ;
			 /*
			 printf("ep is: ");
  	for(i=7; i>=0; i--){
  		printf("%d", (ep >> i) & 0x01);
  	}
  	printf("\n");
  	*/
	epxk1 = ep ^ key;
	row = (epxk1 & 0x80) >> 6 | (epxk1 & 0x10) >> 4;
	col = (epxk1 & 0x40) >> 5 | (epxk1 & 0x20) >> 5;
	tp4 = s0[row][col] << 2;
	row = (epxk1 & 0x08) >> 2 | (epxk1 & 0x01);
	col = (epxk1 & 0x04) >> 1 | (epxk1 & 0x02) >> 1;
	tp4 = tp4 | s1[row][col];
	p4 = (tp4 & 0x08) >> 3 | (tp4 & 0x04) << 1 |
			 (tp4 & 0x02)      | (tp4 & 0x01) << 2 ; 
	
	return (p4 << 4) ^ ip;
}
uint8_t swap(uint8_t fkOut){
	return (fkOut & 0x80) >> 4 | (fkOut & 0x40) >> 4 |
				 (fkOut & 0x20) >> 4 | (fkOut & 0x10) >> 4 |
				 (fkOut & 0x08) << 4 | (fkOut & 0x04) << 4 |
				 (fkOut & 0x02) << 4 | (fkOut & 0x01) << 4 ;
}
uint8_t IP(uint8_t chain){
	return 		(chain & 0x80) >> 3 | (chain & 0x40) << 1 |
					  (chain & 0x20)      | (chain & 0x10) >> 1 |
				 	  (chain & 0x08) >> 2 | (chain & 0x04) << 4 |
				 		(chain & 0x02) >> 1 | (chain & 0x01) << 2 ;
}
uint8_t invip(uint8_t fksw){
	return 		(fksw & 0x80) >> 1 | (fksw & 0x40) >> 4 |
					  (fksw & 0x20)      | (fksw & 0x10) << 3 |
				 	  (fksw & 0x08) << 1 | (fksw & 0x04) >> 2 |
				 		(fksw & 0x02) << 2 | (fksw & 0x01) << 1 ;
}
