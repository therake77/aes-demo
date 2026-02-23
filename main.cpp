#include <fstream>
#include <iostream>
#include <aes.hpp>

int main(){
    /*
    SpecialFileReader sfr = SpecialFileReader("input.txt");
    while(sfr.hasNext()){
        char* text = sfr.readNextChunk(16);
        std::cout<<text<<std::endl;
        delete text;
    }*/
    try{
        AES_Cipher cipher = AES_Cipher( (AES_128_key){
        'a','b','c','d',
        'a','b','c','d',
        'a','b','c','d',
        'a','b','c','d'
        });
        std::cout<<"cipher initialized"<<std::endl;
    }catch( std::exception e){
        std::cout<<e.what()<<std::endl;
    }
    std::cout<<"Test passed"<<std::endl;
    return 0;
}