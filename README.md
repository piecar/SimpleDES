# SimpleDES
A simple encryption using S-DES (Simplified DES) with Cipher Block Chaining (CBC).
The program takes the input of an initial key and an initial vector, reads the plaintext (or ciphertext) from a file, conducts the encryption (or decryption), and writes the resulting ciphertext (or plaintext) into a second file. 
The program should take a command in the following format:

% mycipher [-d] init_key init_vector original_file result_file

where <init_key> is the 10-bit initial key (written plainly as ones and zeros in the command line). <init_vector> is the 8-bit initial vector (also written plainly as ones and zeros). <original_file> is the name of the file to be encrypted or decrypted. <result_file> is the name of the file containing the result of the encryption or decryption. With the -d option, the program does decryption; without it, the program does encryption. 
