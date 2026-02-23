#include <string>
#include <fstream>
#include <exception>

class SpecialFileReader{
    std::fstream fs;
    bool eof = false;
public:

    SpecialFileReader() = delete;
    SpecialFileReader(std::string);

    int readNextChunk(char* ,std::size_t);
    void goToBegin();
    bool hasNext();
    void close();
};

class SpecialFileReaderException : std::exception{
    const char* msg;
public:
    SpecialFileReaderException();
    SpecialFileReaderException(const char* c);
    const char* what() const noexcept override;
};