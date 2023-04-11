#include <iostream>
#include<fstream>
#include<sstream>
#include<string>
#include <chrono>
#include <thread>
using namespace std;

int a = 0;
int magicNum = 1337;

void thrdFn() {
        a++;
        cout << "seen1: " << a << '\n';
        //std::this_thread::sleep_for(100ms);
        
    }  


//if argv[1] == 1337 ==> data race
int main(int argc, char *argv[])
{
    
    int inputNum = 0;

    if(argc == 2) {
        string inFile = "";
        inFile = argv[1];
        
        ifstream input_file(inFile); //taking file as inputstream
        string str;
        if (input_file.is_open()) {
            int number;
            while (input_file >> number) {
                inputNum = number;
                cout << "number:" << number << endl;
                break;
            }
        }
        else {
            cout << "file not open:" << inFile << endl;
            return 0;
        }
        cout << "inputNum:" << inputNum << endl;

    }
    else {
        cout << "wrong num of arguments";
        return 0;
    }

    thread thr(&thrdFn);

    if(inputNum > 0) {
        if(inputNum < 2000) {
            if(inputNum > 1100) {
                if(inputNum > 1300) {
                    if(inputNum < 1400) {
                        a++;
                        cout << "seen2: " << a << '\n';
                        //if(inputNum == magicNum) {
                        //    cout << "seen2: " << a << '\n';
                        //}
                    }
                }
            }
        }
        else {
            cout << "not2 \n";
        }
    }    
    //std::this_thread::sleep_for(50ms);

    
    
    thr.join();
    
    cout << "end of program";
    return 0;
}