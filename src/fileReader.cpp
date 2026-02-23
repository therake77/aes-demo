#include <fileReader.hpp>

SpecialFileReader::SpecialFileReader(std::string path){
    this->fs = std::fstream(path, std::ios::in | std::ios::binary);
    if(!fs.is_open()){
        throw SpecialFileReaderException("SpecialFileReader: Invalid file path");
    }
}

/*Fills a buffer with at most `size` characters */
int SpecialFileReader::readNextChunk(char* buff, std::size_t size){
    if(fs.good()){
        this->fs.read(buff,size);
        if(fs.fail()){
            if(!fs.eofbit){
                throw SpecialFileReaderException("readNextChunk: Error at reading");
            }else{
                this->eof = true;
            }
        }
        return fs.gcount();
    }
    return -1;
}

void SpecialFileReader::goToBegin(){
    this->fs.seekg(0);
}

bool SpecialFileReader::hasNext(){
    return !eof;
}

void SpecialFileReader::close(){
    this->fs.close();
}

/* Exception declarations*/

SpecialFileReaderException::SpecialFileReaderException(){
    this->msg = "";
}

SpecialFileReaderException::SpecialFileReaderException(const char* c) : msg(c){}

const char* SpecialFileReaderException::what() const noexcept{
    return this->msg;
}