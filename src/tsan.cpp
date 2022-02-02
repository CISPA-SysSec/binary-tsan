#include <iostream>
#include <irdb-util>
#include <irdb-core>

#include "tsantransform.h"

#include <iostream>

int main(int argc, char* argv[]) {
    const std::string program_name = std::string(argv[0]);
    const auto variantID = std::strtol(argv[1], nullptr, 10);

    std::vector<std::string> args;
    for(int i = 2; i < argc; i++) {
        args.emplace_back(argv[i]);
    }

    // stand-alone transforms must setup the interface to the sql server
    auto pqxx_interface = IRDB_SDK::pqxxDB_t::factory();
    IRDB_SDK::BaseObj_t::setInterface(pqxx_interface.get());

    // stand-alone transforms must create and read a variant ID from the database
    auto pidp = IRDB_SDK::VariantID_t::factory((int)variantID);
    assert(pidp->isRegistered()==true);

    // stand-alone transforms must create and read the main file's IR from the database
    auto this_file = pidp->getMainFile();
    auto url = this_file->getURL();

    // declare for later so we can return the right value
    bool success = false;

    // now try to load the IR and execute a transform
    try {
        // Create and download the file's IR.
        // Note:  this is achieved differently  with thanos-enabled plugins
        auto firp = IRDB_SDK::FileIR_t::factory(pidp.get(), this_file);

        // sanity
        assert(firp && pidp);

        // log
        std::cout << "Transforming " << this_file->getURL() << std::endl;

        // create and invoke the transform
        TSanTransform tsan(firp.get());
        success = tsan.parseArgs(args);
        if (success) {
            success = tsan.executeStep();
        }

        // conditionally write the IR back to the database on success
        if (success) {
            std::cout << "Writing changes for " << url << std::endl;

            // TODO: check for successfull writeback
            // Stand alone transforms must manually write the IR back to the IRDB and commit the transactions
            firp->writeToDB();

            // and commit the the transaction to postgres
            pqxx_interface->commit();
        } else {
            std::cout << "Skipping write back on failure. " << url << std::endl;
        }
    } catch (const IRDB_SDK::DatabaseError_t &db_error) {
        // log any databse errors that might come up in the transform process
        std::cout << program_name << ": Unexpected database error: " << db_error << "file url: " << url << std::endl;
    } catch (...) {
        // log any other errors
        std::cout<< program_name << ": Unexpected error file url: " << url << std::endl;
    }

    // return success code to driver (as a shell-style return value).  0=success, 1=warnings, 2=errors
    return success ? 0 : 2;
}
