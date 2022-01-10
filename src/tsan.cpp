#include <iostream>
#include <zipr-sdk>

extern "C" Zipr_SDK::ZiprPluginInterface_t* getPluginInterface(Zipr_SDK::Zipr_t* p_zipr_main_object) {
    std::cout <<"Hello world!"<<std::endl;
    return nullptr;
}
